# SentinelX — Offline Security Operations & Detection Platform

SentinelX is an offline-first Security Operations platform for collecting, normalizing, detecting and investigating security activity in restricted or air-gapped environments. It combines the repository's SIEM engine with a FastAPI service and React/TypeScript analyst console.

## Architecture

```text
Logs / Endpoints / Network
            |
            v
     Parsing & Normalization
            |
            v
        Event Store
            |
       +----+----+
       |         |
       v         v
  Detection   Threat Intel
    Engine       Engine
       |         |
       +----+----+
            |
            v
      Alert Generation
            |
            v
      Correlation / Risk
            |
            v
       Incident Cases
            |
       +----+-----+-------+
       |          |       |
       v          v       v
    Timeline   ATT&CK   Reports
       |
       v
  React Console / API / Hunting
```

## Current capabilities

- JSON, JSONL, CSV, syslog and text log parsing into a common schema
- Sliding-window brute-force detection
- Per-user repeated failed-login detection
- Suspicious security-pattern detection
- Offline IP/CIDR threat-intelligence matching
- Statistical anomaly detection
- SQLite storage for events, alerts and incidents
- Deterministic event/alert identifiers for local deduplication
- FastAPI event ingestion and search
- Alert filtering and analyst triage lifecycle
- SOC dashboard summary metrics
- Alert correlation with shared identity/network indicators
- Explainable 0-100 incident risk scoring
- Basic MITRE ATT&CK technique mapping
- Investigation timeline API
- React + TypeScript analyst console
- Docker Compose deployment
- Streamlit SOC dashboard and legacy-compatible workflow
- HTML/TXT investigation reports
- Automated backend and frontend CI validation

## Quick start

### Option 1 — Docker Compose

Build and run the complete local stack:

```bash
docker compose up --build
```

Open the analyst console at `http://127.0.0.1:8080`.

The FastAPI service is available at `http://127.0.0.1:8000` and Swagger documentation at `http://127.0.0.1:8000/docs`.

The SQLite database is stored in the persistent `sentinelx_data` Docker volume.

### Option 2 — Local development

Requirements:

- Python 3.10+
- Node.js 22+

Backend:

```bash
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows
.venv\\Scripts\\activate

pip install -r requirements.txt -r backend/requirements.txt
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Frontend, in a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The Vite development server uses the configured proxy to forward `/api`, `/health` and `/ready` requests to FastAPI.

### Legacy Streamlit interface

```bash
pip install -r requirements.txt
streamlit run app.py
```

## API endpoints

- `GET /health`
- `GET /ready`
- `GET /api/v1`
- `POST /api/v1/events`
- `GET /api/v1/events`
- `GET /api/v1/alerts`
- `PATCH /api/v1/alerts/{alert_uid}/status`
- `GET /api/v1/dashboard/summary`
- `POST /api/v1/incidents`
- `GET /api/v1/incidents`
- `GET /api/v1/incidents/{incident_uid}`
- `PATCH /api/v1/incidents/{incident_uid}/status`
- `GET /api/v1/correlation/preview`
- `POST /api/v1/correlation/run`
- `GET /api/v1/investigation/{incident_uid}/timeline`

## Detection engine

| Detector | Purpose |
|---|---|
| `BruteForceDetector` | Repeated authentication failures within a configurable sliding window |
| `FailedLoginDetector` | Repeated failures against an individual account |
| `KeywordDetector` | Security-relevant patterns such as SQL injection, XSS and privilege escalation |
| `ThreatIntelDetector` | Matches IPv4 addresses and CIDRs against offline intelligence |
| `AnomalyDetector` | Statistical deviations in log activity |

The existing detection engine remains the source of truth for detection logic; the API layer adapts canonical events into its `NormalizedLog` model instead of maintaining a second detector implementation.

## Analyst workflow

1. Ingest or upload security logs.
2. Normalize events into the SentinelX schema.
3. Run the existing detection suite.
4. Persist generated alerts.
5. Triage alerts using status changes.
6. Correlate related alerts.
7. Assign risk and ATT&CK context to the incident.
8. Investigate the timeline and supporting evidence.
9. Generate a report.

## Security design

- Core analysis works without external threat-intelligence APIs.
- Runtime databases, credentials, reports, logs and Python bytecode remain excluded from Git.
- Uploaded content is size-limited in the Streamlit UI.
- API queries use parameterized SQLite statements.
- Raw event content is retained for investigation traceability.
- Browser/API CORS is restricted to local development origins and does not allow credentials.
- The container stack keeps persistent application data in a named volume.

## Testing

Backend and frontend are validated independently:

```bash
pip install -r requirements.txt -r backend/requirements.txt
pytest -q

cd frontend
npm install
npm run build
```

GitHub Actions runs both suites on pushes to `main`/`stabilize-and-harden` and pull requests targeting `main`.

## Project structure

```text
offline-siem/
├── app.py
├── backend/
│   ├── app/
│   ├── tests/
│   └── Dockerfile
├── frontend/
│   ├── src/
│   ├── Dockerfile
│   └── nginx.conf
├── docker-compose.yml
├── config.yaml
├── docs/
├── requirements.txt
├── samples/
├── tests/
└── src/
    ├── analytics/
    ├── detection/
    ├── ingestion/
    ├── parsers/
    ├── reporting/
    ├── security/
    ├── storage/
    └── ui/
```

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md). The next major feature set is advanced threat hunting, richer ATT&CK coverage, evidence management, report generation through the API, and end-to-end attack simulation datasets.

## License

MIT License
