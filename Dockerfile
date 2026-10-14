FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

# Install pinned dependencies first (cached unless the lock file changes)
COPY requirements.txt .
RUN pip install -r requirements.txt

# Only what the agent needs at runtime
COPY triage_agent/ triage_agent/
COPY mcp_server.py policy.json ./
COPY data/alerts.json data/attack.json data/attack_techniques.jsonl data/

# Run as a non-root user
RUN useradd --create-home app && chown -R app:app /app
USER app

# Approval queue goes to /tmp (ephemeral; replaced by a real store later)
ENV QUEUE_FILE=/tmp/pending_actions.jsonl

CMD ["sh", "-c", "exec adk web --host 0.0.0.0 --port ${PORT:-8080} /app"]
