# Alert Triage Agent

An AI agent that triages SOC alerts (Suricata / Wazuh), maps them to MITRE ATT&CK
using retrieval-augmented generation (RAG), and resists prompt injection hidden in
alert data. Built with Google ADK, a custom MCP server, and BigQuery vector search.

## Architecture

```
MITRE ATT&CK STIX -> scripts/prepare_attack.py -> data/attack_techniques.jsonl
                                                        |
                      BigQuery: load -> embed (text-embedding-005) -> VECTOR_SEARCH
                                                        |
alerts.json -> mcp_server.py (MCP over stdio) <---------+
               list_alerts | get_alert | search_attack_techniques | lookup_attack_technique
                    | MCP
               triage_agent (Google ADK + Gemini 2.5 Flash) -> triage report
```

## How the agent maps ATT&CK: search, judge, verify

1. **Search:** describe the observed *behavior* in plain English and retrieve candidate
   techniques from the vector index.
2. **Judge:** candidates are ranked by text similarity, so some are irrelevant. Keep one
   only if the alert evidence supports it.
3. **Verify:** every technique ID cited must be confirmed by `lookup_attack_technique`
   against the full ATT&CK v19 Enterprise list (697 active techniques).

## Security design

- Alert `details` are treated as untrusted, attacker-controlled data. The agent never
  follows instructions found in them and flags suspected prompt injection.
- All tools are read-only. The agent recommends actions and never claims to perform them.
- Search text is passed to BigQuery as a query parameter (no SQL injection), capped at
  500 characters, and `top_k` is clamped.
- The agent must describe behavior in its own words and never copy alert text into a
  search query.
- Technique IDs are verified against the reference list before being cited.

## Findings so far

- Retrieval returns candidates, not answers: rank 1 is not always right, and wording
  matters (a query containing "SSH" surfaced SSH-themed techniques ahead of brute force).
- Recall gap: on a brute-force-then-successful-login incident, the agent did not map
  T1078 (Valid Accounts). Phase 3 will measure this with a labeled eval set.
- Prompt-injection baseline: the agent resisted a prompt-injection payload in a
  User-Agent field using instructions alone. Phase 3 will test this systematically.

## Roadmap

- [x] Phase 1: ADK agent + custom MCP server
- [x] Phase 2: RAG over full MITRE ATT&CK (BigQuery embeddings + vector search)
- [ ] Phase 3: eval set (technique recall@k, hallucination, injection resistance) and guardrails
- [ ] Phase 4: cloud deployment (Cloud Run, CI/CD, Secret Manager)

## Run locally

```
pip install -r requirements.txt
adk web
```

## Rebuild the ATT&CK vector index

Replace `PROJECT_ID` with your Google Cloud project.

```
curl -L -o data/raw/enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
python scripts/prepare_attack.py
bq mk --dataset --location=US triage_rag
bq load --source_format=NEWLINE_DELIMITED_JSON --autodetect triage_rag.attack_techniques data/attack_techniques.jsonl
bq mk --connection --location=US --project_id=PROJECT_ID --connection_type=CLOUD_RESOURCE embedding_conn
# Grant the connection's service account roles/aiplatform.user, then:
bq query --use_legacy_sql=false 'CREATE OR REPLACE MODEL `triage_rag.embedding_model` REMOTE WITH CONNECTION `PROJECT_ID.us.embedding_conn` OPTIONS (ENDPOINT = "text-embedding-005")'
bq query --use_legacy_sql=false 'CREATE OR REPLACE TABLE triage_rag.attack_embeddings AS SELECT * FROM AI.GENERATE_EMBEDDING(MODEL triage_rag.embedding_model, (SELECT *, text AS content FROM triage_rag.attack_techniques)) WHERE LENGTH(status) = 0'
```
