# Alert Triage Agent

An AI SOC alert-triage agent built on Google Cloud. It reads a security alert, maps it to MITRE ATT&CK techniques using retrieval over the real ATT&CK data, gives a verdict, and can *request* containment. A human has to approve it, and code-level guardrails sit in between.

The point of the project is not just the agent. It is how the agent is **measured and constrained**: labeled evals, controlled experiments, a held-out set, and a red-team suite that found a real weakness.

## Architecture

    alert --> ADK agent (Gemini, Vertex AI)
                |  tools via MCP server
                |    search_attack_techniques  -> BigQuery VECTOR_SEARCH over 697 ATT&CK v19 techniques
                |    lookup_attack_technique   -> verify an ID exists before citing it
                |    request_containment       -> server-side policy check, then Firestore approval queue (cannot execute anything)
                |
                +-- before_tool_callback : policy gate     (validates containment targets)
                +-- after_tool_callback  : records seen targets and verified technique IDs
                +-- after_model_callback : citation gate   (tags unverified technique IDs)
                v
            report + verdict   -->   data/pending_actions.jsonl  -->  approve.py (human y/N)

- **Agent:** Google ADK 2.10.0. Workflow is search, judge, verify, then report.
- **RAG:** ATT&CK v19 technique text embedded and searched in BigQuery (`AI.GENERATE_EMBEDDING`, `VECTOR_SEARCH`). The agent retrieves the top 15 candidates and must pick among them.
- **Tools over MCP:** `mcp_server.py` exposes search, lookup and containment-request tools.
- **Human in the loop:** the agent can only *request* `block_ip` or `isolate_host`. `approve.py` is the review CLI. Actions are simulated.

## Guardrails: prompts are probabilistic, code is a guarantee

| Layer | Where | What it enforces |
|---|---|---|
| Approval queue | `request_containment` + `approve.py` | The agent cannot act, only ask. A human decides. |
| Policy gate | `before_tool_callback` | Rejects invalid IPs/CIDRs, loopback/special addresses, bad hostnames, unknown actions, protected assets (`policy.json`), targets that never appeared in the alert data, and more than 3 requests per run. |
| Citation gate | `after_model_callback` | Any technique ID in the final report that was not confirmed by `lookup_attack_technique` is tagged `[UNVERIFIED]`. |
| Server-side policy | inside `mcp_server.py` | The same target rules, enforced in the tool server itself: valid IP/hostname, not a protected asset, and the target must be a structured `src_ip`/`host` field of a real alert. Also rejects duplicate pending requests. Holds even if the agent code is bypassed. |

## Evaluation method

- **Labeled cases:** 25 tuned alerts (C01-C25), 11 held-out alerts (H01-H11), 11 red-team alerts (RT01-RT11).
- **Scoring:** technique recall and precision (parent-technique matching, with `acceptable_techniques` for defensible alternatives), verdict accuracy, hallucinated or unverified IDs, injection resistance, and containment behaviour.
- **3 trials per suite**, because LLM output varies. Each case is reported as pass k/3 and flagged FLAKY or FAILS.
- **One change per experiment.** The agent was frozen (tag `agent-v1-frozen`) before the held-out run, to check for overfitting to the tuned cases.

## Results

### Tuned suite (25 cases x 3 trials)

| Version | Recall | Precision | Verdict | Injection resistance | Passing case-runs |
|---|---|---|---|---|---|
| Baseline | 0.90 | 0.81 | 0.93 | 0.92 | 47/75 |
| + retrieval depth top_k=15 | 0.94 | 0.76 | 0.95 | 0.92 | 43/75 |
| + stricter judge/verdict instructions | 0.94 | 0.89 | 1.00 | 1.00 | 60/75 |
| Final (+ containment, policy gate, citation gate) | 0.95 | 0.90 | 1.00 | 1.00 | 57/75 |

Deeper retrieval fixed recall but let in more wrong candidates (precision fell). Tightening the instructions recovered precision and made verdicts and injection resistance perfect. The final agent adds containment and the gates; changes are within trial-to-trial noise.

### Held-out suite (11 unseen cases x 3 trials)

| Version | Recall | Precision | Verdict | Passing case-runs |
|---|---|---|---|---|
| Frozen v1 | 1.00 | 0.85 | 0.91 | 25/33 |
| Final | 1.00 | 0.88 | 0.97 | 27/33 |

Held-out performance matches the tuned suite, so the gains were not just overfitting to the tuned cases.

### Red team (containment safety)

- **Prompt-injection attacks:** the agent resisted all of them. 0 of 18 produced a bad containment request.
- **Spoofed or reflected "trusted" sources** (alert text claiming a target was approved or internal) **did beat the agent's own rules:** without the code gate, 2 of 9 runs queued a bad request.
- **With the policy gate:** 0 bad requests queued across 33 case-runs, 8 requests stopped by the gate, and 12 of 12 legitimate containment requests still went through.
- **Re-run after adding the server-side gate:** 0 bad requests queued across 33 case-runs, 9 stopped by the agent-side gate, 12 of 12 legitimate requests still went through.

## Design notes

- **The red team changed the design.** Prompt rules held against injection but not against a convincing forged context. The fix was a deterministic gate, not more prompt text.
- **Verify before cite.** Technique IDs are only trusted after a lookup confirms them. ATT&CK v19 renumbered some techniques (for example T1562.001 became T1685), which is the kind of stale-memory error this catches.
- **Search, judge, verify.** Retrieval proposes candidates, the model judges them against the alert, and a lookup confirms each ID.
- **One scoring definition.** A CI gate once disagreed with the reported results because the live scorer ignored `acceptable_verdicts`. Scoring now lives in one module (`evals/scoring.py`) used by both the summary and the gate.

## Known limitations

- **Small samples.** 25 + 11 + 11 cases and 3 trials each. Differences of a few case-runs are noise.
- **Verdict check is substring-based**, so it is a coarse measure.
- **Persistent weak spots:** C01 never reliably finds T1078; C16 sometimes picks external recon (T1595) over network scanning (T1046); C11, C12 and C19 often add extra techniques, which lowers precision; H07 and H09 are the weakest held-out cases.
- **The citation gate is unit-tested but has not fired in a live run.** In every eval the agent had already verified everything it cited. It is a safety net, not a measured improvement.
- **Benign verdicts backed only by text inside the alert are forgeable.** The proper fix is a trusted allowlist or asset-inventory tool, which does not exist yet.
- **The per-run request cap is agent-side only.** The MCP server can serve many sessions, so it enforces session-independent rules (target validity, protected assets, real-alert targets, no duplicates) and leaves "3 requests per run" to the agent callback.
- **Benign alerts are still trusted too easily.** The server checks that a target exists in the alert store, not that an asset is genuinely safe to touch; an allowlist or asset-inventory service would add that.
- **One CI identity both evaluates and deploys.** Splitting it in two would reduce its blast radius.
- **CI evals are a sample.** The pipeline runs 10 reliable tuned cases and the red-team suite with a single trial, as a regression tripwire. It is not a replacement for the full 3-trial suites.
- **Containment is simulated.** Nothing real is blocked or isolated.

## Repository layout

    triage_agent/agent.py    agent, instructions, guardrail callbacks
    mcp_server.py            MCP tools: search, lookup, request_containment
    policy.json              protected assets and request limits
    approve.py               human review CLI for the approval queue
    evals/                   cases.jsonl, holdout.jsonl, redteam.jsonl, eval_agent.py, summarize.py, saved results

Run an eval: `EVAL_TAG=mytag python evals/eval_agent.py`, then `python evals/summarize.py evals/results_mytag.json`.

## Run the agent

From the project root, with the virtual environment active and `triage_agent/.env` set (Vertex AI project and location):

    adk web --port 8080

In Cloud Shell, also pass `--allow_origins` with your web-preview URL. Then open the preview on port 8080 and pick `triage_agent`.

## Deployment

- **Cloud Run** (us-central1): private (no unauthenticated access), scale-to-zero, maximum one instance, running as a dedicated least-privilege service account.
- The MCP server runs in the same container as a subprocess and receives an allowlisted set of environment variables, not the whole environment.
- **Approval queue:** Firestore (`pending_actions`, `decisions`). `QUEUE_BACKEND=firestore python approve.py` is the human review step; the reviewer uses their own credentials, never the agent's.
- Try it yourself: `gcloud run services proxy triage-agent --region us-central1 --port 8080`, then open Cloud Shell Web Preview on port 8080.
- `scripts/setup_cloud.sh` records the cloud setup (written from the manual steps, not re-run as one script); `scripts/teardown.sh` removes everything it created.

## CI/CD

GitHub Actions (`.github/workflows/ci-cd.yml`), on every push to `main`:

1. Unit tests for the server-side policy (no LLM, free).
2. An eval subset with a quality floor (mean recall 0.85, mean precision 0.75). Hard stops: any hallucinated or unverified ID, or any bad containment request queued. Behaviour checks (verdict, injection handling, expected containment) tolerate one miss, because a single-trial LLM run wobbles; two misses fail the pipeline.
3. The red-team suite under the same hard stops and one-miss tolerance.
4. Deploy to Cloud Run, only if every earlier stage passed.

Authentication is keyless (Workload Identity Federation): no service-account key exists anywhere. Google accepts GitHub's short-lived token only for pushes to `main` of this repository.

The deploy job builds the image on the runner, pushes it to Artifact Registry tagged with the commit hash, and deploys that image, so every running revision traces back to the exact commit. The deployer identity has no Cloud Build or storage-bucket permissions.

## Roadmap

Split the CI identity, add an asset-inventory tool for benign verdicts, and widen the CI eval sample.

## License

MIT
