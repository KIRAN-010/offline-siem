# SentinelX Backend

FastAPI service for the SentinelX SOC platform.

## Run locally

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

API endpoints currently available:

- `GET /health` — liveness check
- `GET /ready` — readiness check
- `GET /api/v1` — service/module information

Interactive API documentation is available from FastAPI at `/docs` when the development server is running.
