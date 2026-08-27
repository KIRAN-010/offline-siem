# SentinelX — Offline Security Operations & Detection Platform

SentinelX is an offline-first Security Operations platform for collecting, normalizing, detecting and investigating security activity in restricted or air-gapped environments. It combines the repository's SIEM engine with a FastAPI service for event ingestion, alert triage, dashboard telemetry and incident case management.

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
     SOC UI / API / Hunting
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
- Incident/case creation from related alert identifiers
- Streamlit SOC dashboard
- HTML/TXT investigation reports
- Automated regression tests with GitHub Actions

## Quick start

### Requirements

- Python 3.10+
- Windows, Linux or macOS

```bash
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows
.venv\\Scripts\\activate

pip install -r requirements.txt
streamlit run app.py
```

### API service

```bash
pip install -r backend/requirements.txt
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Swagger documentation is available at `http://127.0.0.1:8000/docs` while the API is running.

### API endpoints

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
6. Group related alerts into an incident case.
7. Investigate evidence and timeline activity.
8. Generate a report.

## Security design

- Core analysis works without external threat-intelligence APIs.
- Runtime databases, credentials, reports, logs and Python bytecode remain excluded from Git.
- Uploaded content is size-limited in the Streamlit UI.
- API queries use parameterized SQLite statements.
- Raw event content is retained for investigation traceability.
- Incident and alert data are stored locally for restricted environments.

## Testing

```bash
pip install -r requirements.txt -r backend/requirements.txt
pytest -q
```

GitHub Actions runs the regression suite for pushes to `main`/`stabilize-and-harden` and pull requests targeting `main`.

## Project structure

```text
offline-siem/
├── app.py
├── backend/
│   ├── app/
│   └── tests/
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

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the implementation milestones. The next major feature is automated alert correlation/risk scoring followed by threat hunting and a full analyst dashboard.

## License

MIT License
