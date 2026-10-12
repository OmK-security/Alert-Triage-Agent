"""Turn the raw MITRE ATT&CK bundle into one clean record per technique."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw" / "enterprise-attack.json"
OUT = ROOT / "data" / "attack_techniques.jsonl"
MAX_CHARS = 6000  # ~1,500 tokens, safely under the embedding model's limit


def clean(text):
    """Strip citation markers and markdown links, collapse whitespace."""
    text = re.sub(r"\(Citation: [^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def get_attack_id(obj):
    """Return (technique_id, url) from the 'mitre-attack' external reference."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref["external_id"], ref.get("url")
    return None, None


def main():
    with open(RAW, encoding="utf-8") as f:
        bundle = json.load(f)

    records = []
    truncated = 0

    for obj in bundle["objects"]:
        if obj["type"] != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id, url = get_attack_id(obj)
        if technique_id is None:
            continue

        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        description = clean(obj.get("description", ""))
        text = f"{obj['name']}. Tactics: {', '.join(tactics)}. {description}"

        if len(text) > MAX_CHARS:
            text = text[:MAX_CHARS]
            truncated += 1

        records.append({
            "technique_id": technique_id,
            "name": obj["name"],
            "tactics": tactics,
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            "platforms": obj.get("x_mitre_platforms", []),
            "url": url,
            "text": text,
        })

    records.sort(key=lambda r: r["technique_id"])

    with open(OUT, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    longest = max(len(r["text"]) for r in records)
    print(f"{len(records)} records written, {truncated} truncated, longest text {longest} chars")


if __name__ == "__main__":
    main()
