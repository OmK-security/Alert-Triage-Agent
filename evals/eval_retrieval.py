"""Retrieval eval: does the right ATT&CK technique appear in the top-k results?"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import mcp_server  # noqa: E402  (reuses the exact search code the agent uses)

KS = [1, 3, 5, 8, 15]


def is_hit(candidate_id, expected_id):
    """Parent-level match: expected T1110 is satisfied by T1110 or T1110.001."""
    return candidate_id == expected_id or candidate_id.startswith(expected_id + ".")


def rank_of(expected_id, results):
    for i, r in enumerate(results, start=1):
        if is_hit(r["technique_id"], expected_id):
            return i
    return None


def main():
    with open(ROOT / "evals" / "cases.jsonl", encoding="utf-8") as f:
        cases = [json.loads(line) for line in f]
    cases = [c for c in cases if c["expected_techniques"]]  # skip benign / no-technique cases

    forms = {
        "signature only": lambda a: a["signature"],
        "signature + details": lambda a: f'{a["signature"]}. {a["details"]}',
    }

    for form_name, build in forms.items():
        rows = []  # (case_id, expected_id, rank, is_injection_case)
        for c in cases:
            query = " ".join(build(a) for a in c["alerts"])
            results = mcp_server.search_attack_techniques(query, top_k=15)
            for exp in c["expected_techniques"]:
                rows.append((c["id"], exp, rank_of(exp, results), c["injection"]))

        print(f"\n=== Query form: {form_name} ===")
        for cid, exp, rank, inj in rows:
            tag = "  [injection case]" if inj else ""
            print(f"{cid} {exp:<10} rank={rank if rank else 'miss'}{tag}")

        n = len(rows)
        summary = "  ".join(
            f"recall@{k}={sum(1 for r in rows if r[2] and r[2] <= k) / n:.2f}" for k in KS
        )
        print(f"\n{form_name}: {n} expected techniques -> {summary}")


if __name__ == "__main__":
    main()
