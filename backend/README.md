# SentinelX Backend

Run these commands from the repository root, so the shared detection package and configuration are available:

```bash
python -m pip install -r requirements.txt -r backend/requirements.txt
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Interactive endpoint documentation is available at http://127.0.0.1:8000/docs.

The service supports event ingestion/search, offline file imports, detections, rules, alert triage, incident correlation/status, timelines, analyst notes, evidence links, JSON/HTML/text reports and saved searches. SQLite persists analyst work locally.

`GET /health` checks liveness; `GET /ready` also checks database access.

Run the complete Python suite from the repository root:

```bash
python -m pytest -q
```

This is a local analyst tool without API authentication. Keep it on loopback or behind your own authenticated gateway.
