import json
import os
import ipaddress
import re
import time
import uuid
from pathlib import Path

from google.cloud import bigquery
from mcp.server.fastmcp import FastMCP

DATA_DIR = Path(__file__).parent / "data"
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "smooth-epsilon-rxjsq")
ALERTS_FILE = Path(os.getenv("ALERTS_FILE", DATA_DIR / "alerts.json"))
mcp = FastMCP("alert-triage")

# Full ATT&CK reference (697 active techniques), loaded once at startup.
TECHNIQUES = {}
with open(DATA_DIR / "attack_techniques.jsonl", encoding="utf-8") as f:
    for line in f:
        rec = json.loads(line)
        TECHNIQUES[rec["technique_id"]] = rec

# The text is passed as a query PARAMETER (@behavior), never pasted into the SQL.
SEARCH_SQL = """
SELECT base.technique_id AS technique_id, base.name AS name,
       base.tactics AS tactics, base.text AS text, distance
FROM VECTOR_SEARCH(
  TABLE triage_rag.attack_embeddings, 'embedding',
  (SELECT embedding FROM AI.GENERATE_EMBEDDING(
     MODEL triage_rag.embedding_model,
     (SELECT @behavior AS content))),
  top_k => {top_k}, distance_type => 'COSINE')
ORDER BY distance
"""

_bq_client = None


def _bq():
    """Create the BigQuery client on first use, not at server start."""
    global _bq_client
    if _bq_client is None:
        _bq_client = bigquery.Client(project=PROJECT_ID)
    return _bq_client


@mcp.tool()
def list_alerts() -> list[dict]:
    """Return all current security alerts."""
    with open(ALERTS_FILE, encoding="utf-8") as f:
        return json.load(f)


@mcp.tool()
def get_alert(alert_id: str) -> dict:
    """Return one alert by its ID, e.g. 'ALR-0003'."""
    with open(ALERTS_FILE, encoding="utf-8") as f:
        alerts = json.load(f)
    for a in alerts:
        if a["alert_id"] == alert_id.strip():
            return a
    return {"found": False, "alert_id": alert_id}


@mcp.tool()
def search_attack_techniques(behavior: str, top_k: int = 15) -> list[dict]:
    """Semantic search over MITRE ATT&CK. Describe the observed BEHAVIOR in plain
    English (e.g. 'repeated failed logins followed by a successful login'), not
    just a protocol or tool name. Returns CANDIDATE techniques ranked by
    similarity (lower distance = closer). Candidates are NOT verified matches:
    check each one against the alert evidence before using it."""
    behavior = behavior.strip()[:500]  # cap the input length
    if not behavior:
        return [{"error": "behavior must not be empty"}]
    top_k = max(1, min(int(top_k), 15))  # clamp to a safe range
    job = _bq().query(
        SEARCH_SQL.format(top_k=top_k),
        job_config=bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("behavior", "STRING", behavior)
            ]
        ),
    )
    return [
        {
            "technique_id": r["technique_id"],
            "name": r["name"],
            "tactics": list(r["tactics"]),
            "distance": round(r["distance"], 3),
            "summary": r["text"][:300],
        }
        for r in job.result()
    ]


@mcp.tool()
def lookup_attack_technique(technique_id: str) -> dict:
    """Verify a MITRE ATT&CK technique ID is real and return its name and tactics.
    ALWAYS call this before citing a technique ID in a report."""
    tid = technique_id.strip().upper()
    rec = TECHNIQUES.get(tid)
    if rec:
        return {"found": True, "technique_id": tid,
                "name": rec["name"], "tactics": rec["tactics"]}
    return {"found": False, "technique_id": tid,
            "note": "Not an active technique in the Enterprise ATT&CK reference. Do not cite it."}


# ---------------------------------------------------------------------------
# Containment requests. The agent can ASK for an action; it can never EXECUTE one.
# Requests go to an approval queue that only a human (approve.py) can act on.
# ---------------------------------------------------------------------------
QUEUE_FILE = Path(os.getenv("QUEUE_FILE", DATA_DIR / "pending_actions.jsonl"))
ALLOWED_ACTIONS = {"block_ip", "isolate_host"}

# ---------------------------------------------------------------------------
# Server-side policy: enforced HERE, so it holds no matter which client calls the tool.
# ---------------------------------------------------------------------------
_POLICY = json.loads((Path(__file__).parent / "policy.json").read_text())
_PROTECTED = {x.lower() for x in _POLICY["protected_hosts"] + _POLICY["protected_ips"]}
_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")


def _alert_targets() -> set:
    """Every src_ip / host that appears as a structured field in the alert store."""
    found = set()

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k in ("src_ip", "host") and isinstance(v, str):
                    found.add(v.strip().lower())
                else:
                    walk(v)
        elif isinstance(x, list):
            for item in x:
                walk(item)

    with open(ALERTS_FILE, encoding="utf-8") as f:
        walk(json.load(f))
    return found


def _policy_problem(action: str, target: str):
    """Return a reason string if the request breaks policy, else None."""
    t = target.lower()
    if action == "block_ip":
        try:
            ip = ipaddress.ip_address(t)
        except ValueError:
            return "block_ip needs a single valid IP address"
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
            return "not a blockable address"
    elif not _HOST_RE.match(t):
        return "invalid hostname"
    if t in _PROTECTED:
        return "protected asset: containment needs a human decision"
    if t not in _alert_targets():
        return "target is not a src_ip or host of any known alert"
    return None


# ---------------------------------------------------------------------------
# Approval queue backends: a local file (dev/evals) or Firestore (deployed).
# ---------------------------------------------------------------------------
QUEUE_BACKEND = os.getenv("QUEUE_BACKEND", "file")
_fs = None


def _firestore():
    global _fs
    if _fs is None:
        from google.cloud import firestore
        _fs = firestore.Client(project=PROJECT_ID)
    return _fs


def _has_pending(action: str, target: str) -> bool:
    if QUEUE_BACKEND == "firestore":
        from google.cloud.firestore_v1.base_query import FieldFilter
        q = (_firestore().collection("pending_actions")
             .where(filter=FieldFilter("status", "==", "pending"))
             .where(filter=FieldFilter("action", "==", action))
             .where(filter=FieldFilter("target", "==", target)).limit(1))
        return any(True for _ in q.stream())
    if not QUEUE_FILE.exists():
        return False
    with open(QUEUE_FILE, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("status") == "pending" and r["action"] == action and r["target"] == target:
                return True
    return False


def _queue_add(req: dict) -> None:
    if QUEUE_BACKEND == "firestore":
        _firestore().collection("pending_actions").document(req["request_id"]).set(req)
        return
    with open(QUEUE_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(req) + "\n")


@mcp.tool()
def request_containment(action: str, target: str, reason: str) -> dict:
    """Ask a HUMAN analyst to approve a containment action.

    This does NOT execute anything. It only adds a request to an approval queue.
    action: 'block_ip' or 'isolate_host'.
    target: the IP address or hostname taken from the alert's own src_ip or host
            field, exactly as written there.
    reason: one sentence of evidence-based justification.
    Only request containment for a confirmed true positive.
    """
    action = (action or "").strip().lower()
    target = (target or "").strip()[:128]
    reason = (reason or "").strip()[:500]
    if action not in ALLOWED_ACTIONS:
        return {"status": "rejected", "error": f"action must be one of {sorted(ALLOWED_ACTIONS)}"}
    if not target:
        return {"status": "rejected", "error": "target is required"}
    problem = _policy_problem(action, target)
    if problem:
        return {"status": "rejected_by_server_policy", "error": problem,
                "note": "No request was queued."}
    if _has_pending(action, target):
        return {"status": "duplicate", "error": "an identical request is already pending"}
    req = {"request_id": uuid.uuid4().hex[:8], "ts": time.time(), "action": action,
           "target": target, "reason": reason, "status": "pending"}
    _queue_add(req)
    return {"status": "queued_for_human_approval", "request_id": req["request_id"],
            "note": "Nothing has been executed. A human must approve this request."}


if __name__ == "__main__":
    mcp.run()
