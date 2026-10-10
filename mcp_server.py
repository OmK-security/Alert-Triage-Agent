import json
from pathlib import Path
from mcp.server.fastmcp import FastMCP

DATA_DIR = Path(__file__).parent / "data"
mcp = FastMCP("alert-triage")


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
def lookup_attack_technique(technique_id: str) -> dict:
    """Verify a MITRE ATT&CK technique ID is real and return its name.
    ALWAYS call this before citing a technique ID in a report."""
    with open(DATA_DIR / "attack.json") as f:
        attack = json.load(f)
    tid = technique_id.strip().upper()
    if tid in attack:
        return {"found": True, "technique_id": tid, "name": attack[tid]}
    return {"found": False, "technique_id": tid,
            "note": "Not in the local reference list, which is only a small subset of ATT&CK. Treat as UNVERIFIED, not necessarily invalid."}


if __name__ == "__main__":
    mcp.run()
