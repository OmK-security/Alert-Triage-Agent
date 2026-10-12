import json
import os
from pathlib import Path

from google.cloud import bigquery
from mcp.server.fastmcp import FastMCP

DATA_DIR = Path(__file__).parent / "data"
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "smooth-epsilon-rxjsq")
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
    with open(DATA_DIR / "alerts.json") as f:
        return json.load(f)


@mcp.tool()
def get_alert(alert_id: str) -> dict:
    """Return one alert by its ID, e.g. 'ALR-0003'."""
    with open(DATA_DIR / "alerts.json") as f:
        alerts = json.load(f)
    for a in alerts:
        if a["alert_id"] == alert_id.strip():
            return a
    return {"found": False, "alert_id": alert_id}


@mcp.tool()
def search_attack_techniques(behavior: str, top_k: int = 8) -> list[dict]:
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


if __name__ == "__main__":
    mcp.run()
