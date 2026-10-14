"""Summarize several eval runs: per-case pass rate across trials + aggregate means.

Usage: python evals/summarize.py evals/results_base1.json evals/results_base2.json ...
"""
import json
import sys


from scoring import CASES, matches, passed, rescore  # noqa: E402,F401
from pathlib import Path  # noqa: E402,F401


runs = [json.load(open(f, encoding="utf-8")) for f in sys.argv[1:]]
for _run in runs:
    for _r in _run:
        rescore(_r)
n = len(runs)
by_case = {}
for run in runs:
    for r in run:
        by_case.setdefault(r["id"], []).append(r)

print(f"{'case':5} {'name':36} {'pass':5} recall  prec  verdict")
for cid in sorted(by_case):
    rs = by_case[cid]
    ok = [r for r in rs if "score" in r]
    p = sum(passed(r) for r in rs)
    rec = [r["score"]["recall"] for r in ok if r["score"]["recall"] is not None]
    prec = [r["score"]["precision"] for r in ok]
    ver = sum(r["score"]["verdict_ok"] for r in ok)
    flag = "  <- FLAKY" if 0 < p < len(rs) else ("  <- FAILS" if p == 0 else "")
    print(f"{cid:5} {rs[0].get('name','')[:36]:36} {p}/{len(rs)}   "
          f"{(sum(rec)/len(rec)) if rec else float('nan'):5.2f}  {sum(prec)/len(prec):4.2f}  {ver}/{len(ok)}{flag}")


def per_run(run, f):
    vals = [f(r["score"]) for r in run if "score" in r]
    return vals


def rng(vals):
    return f"{sum(vals)/len(vals):.2f}  (min {min(vals):.2f}, max {max(vals):.2f})"


print(f"\n=== {n} runs, across-run mean (min..max) ===")
rec_runs = []
for run in runs:
    v = [r["score"]["recall"] for r in run if "score" in r and r["score"]["recall"] is not None]
    if v:
        rec_runs.append(sum(v) / len(v))
if rec_runs:
    print("technique recall:    ", rng(rec_runs))
print("avg precision:       ", rng([sum(per_run(run, lambda s: s["precision"])) / len(per_run(run, lambda s: s["precision"])) for run in runs]))
print("verdict accuracy:    ", rng([sum(per_run(run, lambda s: s["verdict_ok"])) / len(per_run(run, lambda s: s["verdict_ok"])) for run in runs]))
inj = [[r["score"]["injection_ok"] for r in run if "score" in r and "injection_ok" in r["score"]] for run in runs]
if any(inj):
    print("injection resistance:", rng([sum(x) / len(x) for x in inj if x]))
print("hallucinated IDs:    ", sum(len(r["score"]["hallucinated"]) for run in runs for r in run if "score" in r))
print("unverified citations:", sum(len(r["score"]["unverified"]) for run in runs for r in run if "score" in r))
crs = [r["score"] for run in runs for r in run if "score" in r and "attempted_bad" in r["score"]]
if crs:
    print(f"bad containment requests: attempted {sum(c['attempted_bad'] for c in crs)}, "
          f"QUEUED {sum(c['queued_bad'] for c in crs)}  (over {len(crs)} case-runs)")
    print(f"requests stopped by the policy gate: {sum(c.get('blocked', 0) for c in crs)}")
    ut = [c["requested_expected"] for c in crs if c["requested_expected"] is not None]
    if ut:
        print(f"legit containment requested: {sum(ut)}/{len(ut)}")
flagged = sum(r.get('report', '').count('[UNVERIFIED]') for run in runs for r in run)
print(f'citations tagged [UNVERIFIED] by the citation gate: {flagged}')
allp = [passed(r) for run in runs for r in run]
print(f"cases fully passing: {sum(allp)}/{len(allp)} case-runs")
