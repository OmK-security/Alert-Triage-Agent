"""Human approval step for containment requests queued by the triage agent.

Usage:  python approve.py                       (local file queue)
        QUEUE_BACKEND=firestore python approve.py   (the deployed service's queue)

The agent can only QUEUE requests. This script is where a person reviews each one.
Approval here is simulated: it records the decision and prints what a production
integration would do (call the firewall/EDR API with its own least-privilege credentials).
The reviewer uses their OWN credentials; the agent's identity is never used to approve.
"""
import json
import os
import time
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent
QUEUE = ROOT / "data" / "pending_actions.jsonl"
LOG = ROOT / "data" / "decisions.jsonl"
BACKEND = os.getenv("QUEUE_BACKEND", "file")
PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT", "smooth-epsilon-rxjsq")


@lru_cache(maxsize=1)
def _db():
    from google.cloud import firestore
    return firestore.Client(project=PROJECT)


def _read_file_queue():
    if not QUEUE.exists():
        return []
    return [json.loads(line) for line in QUEUE.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_pending():
    if BACKEND == "firestore":
        from google.cloud.firestore_v1.base_query import FieldFilter
        docs = _db().collection("pending_actions").where(filter=FieldFilter("status", "==", "pending")).stream()
        found = [d.to_dict() for d in docs]
    else:
        found = [r for r in _read_file_queue() if r.get("status") == "pending"]
    return sorted(found, key=lambda r: r.get("ts", 0))


def record(r):
    """Save one finished decision (r already carries status and decided_at)."""
    if BACKEND == "firestore":
        _db().collection("pending_actions").document(r["request_id"]).set(r)
        _db().collection("decisions").document(r["request_id"]).set(r)
        return
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(r) + "\n")
    reqs = _read_file_queue()
    for q in reqs:
        if q["request_id"] == r["request_id"]:
            q.update(r)
    QUEUE.write_text("\n".join(json.dumps(q) for q in reqs) + "\n", encoding="utf-8")


def main():
    pending = load_pending()
    if not pending:
        print(f"No pending requests ({BACKEND} queue).")
        return
    print(f"{len(pending)} pending request(s) in the {BACKEND} queue\n")
    for r in pending:
        print(f"[{r['request_id']}] {r['action']} -> {r['target']}")
        print(f"   reason: {r['reason']}")
        answer = input("   approve? [y/N/q=quit] ").strip().lower()
        if answer == "q":
            break
        r["status"] = "approved" if answer == "y" else "denied"
        r["decided_at"] = time.time()
        record(r)
        if r["status"] == "approved":
            print(f"   SIMULATED: would now run {r['action']} on {r['target']}")
        else:
            print("   denied - no action taken")


if __name__ == "__main__":
    main()
