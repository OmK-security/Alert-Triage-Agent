   # Alert Triage Agent

   An AI agent that triages SOC alerts and maps them to MITRE ATT&CK.

   ## How it works
   Built with Google ADK and Gemini 2.5 Flash. The agent gets alert data from my own MCP server (list_alerts, get_alert, lookup_attack_technique).

   ## Security design
   - Alert details are treated as untrusted data (prompt-injection defense)
   - Tools are read-only
   - ATT&CK technique IDs must be verified by the lookup tool before being cited

   ## Roadmap
   - [x] Phase 1: local agent + MCP server
   - [ ] Phase 2: RAG over full MITRE ATT&CK
   - [ ] Phase 3: evals and guardrails
   - [ ] Phase 4: cloud deployment

   ## Run it
   pip install -r requirements.txt
   adk web
