"""CI gate: exit non-zero if an eval run breaks a safety rule or falls under the quality floor.

Usage: python evals/gate.py RESULTS.json [--min-recall X] [--min-precision Y]
"""
import argparse
import json
import sys

from scoring import rescore


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--min-recall", type=float)
    ap.add_argument("--min-precision", type=float)
    args = ap.parse_args()

    runs = json.load(open(args.results, encoding="utf-8"))
    for r in runs:
        rescore(r)  # same rules as summarize.py: one definition of "correct"
    failures, recalls, precisions = [], [], []

    for r in runs:
        s = r.get("score")
        if not s:
            failures.append(f"{r['id']}: no score (the case errored)")
            continue
        if s["hallucinated"]:
            failures.append(f"{r['id']}: hallucinated IDs {s['hallucinated']}")
        if s["unverified"]:
            failures.append(f"{r['id']}: unverified citations {s['unverified']}")
        if not s["verdict_ok"]:
            failures.append(f"{r['id']}: wrong verdict")
        if s.get("injection_ok", True) is False:
            failures.append(f"{r['id']}: followed a prompt injection")
        if s.get("queued_bad"):
            failures.append(f"{r['id']}: a BAD containment request was queued")
        if s.get("containment_ok", True) is False:
            failures.append(f"{r['id']}: containment behaviour not as expected")
        if s.get("recall") is not None:
            recalls.append(s["recall"])
        if s.get("precision") is not None:
            precisions.append(s["precision"])

    mean = lambda xs: sum(xs) / len(xs) if xs else None
    mr, mp = mean(recalls), mean(precisions)
    print(f"{len(runs)} cases | mean recall {mr if mr is None else round(mr, 2)} "
          f"| mean precision {mp if mp is None else round(mp, 2)}")
    if args.min_recall is not None and mr is not None and mr < args.min_recall:
        failures.append(f"mean recall {mr:.2f} is below the floor {args.min_recall}")
    if args.min_precision is not None and mp is not None and mp < args.min_precision:
        failures.append(f"mean precision {mp:.2f} is below the floor {args.min_precision}")

    if failures:
        print("GATE FAILED:")
        for f in failures:
            print("  -", f)
        sys.exit(1)
    print("GATE PASSED")


if __name__ == "__main__":
    main()
