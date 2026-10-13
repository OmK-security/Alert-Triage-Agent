"""Human approval step for containment requests queued by the triage agent.

Usage:  python approve.py

The agent can only QUEUE requests. This script is where a person reviews each one.
Approval here is simulated: it records the decision and prints what a production
integration would do (call the firewall/EDR API with its own least-privilege credentials).
"""
import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
QUEUE = ROOT / "data" / "pending_actions.jsonl"
LOG = ROOT / "data" / "decisions.jsonl"


def main():
    if not QUEUE.exists():
        print("No queue file yet - nothing to review.")
        return
    reqs = [json.loads(line) for line in QUEUE.read_text(encoding="utf-8").splitlines() if line.strip()]
    pending = [r for r in reqs if r.get("status") == "pending"]
    if not pending:
        print("No pending requests.")
        return
    print(f"{len(pending)} pending request(s)\n")
    for r in pending:
        print(f"[{r['request_id']}] {r['action']} -> {r['target']}")
        print(f"   reason: {r['reason']}")
        answer = input("   approve? [y/N/q=quit] ").strip().lower()
        if answer == "q":
            break
        r["status"] = "approved" if answer == "y" else "denied"
        r["decided_at"] = time.time()
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(r) + "\n")
        if r["status"] == "approved":
            print(f"   SIMULATED: would now run {r['action']} on {r['target']}")
        else:
            print("   denied - no action taken")
    QUEUE.write_text("\n".join(json.dumps(r) for r in reqs) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
