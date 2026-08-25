# Offline SIEM — Security Operations Center

A defensive, offline Security Information and Event Management (SIEM) platform for security analysis in air-gapped or restricted environments.

## What it does

```text
Log files → Parser/Normalization → Detection Engine → Alerts → Investigation
                                      ↓
                         Threat Intel / Analytics
                                      ↓
                           Incident + Reporting
```

### Core capabilities

- JSON, JSONL, CSV, syslog and text log parsing into a common schema
- Sliding-window brute-force detection
- Per-user repeated failed-login detection
- Suspicious security-pattern detection
- Offline IP/CIDR threat-intelligence matching
- Statistical anomaly detection
- SQLite session, log, alert, incident and audit storage
- Search, filtering, grouping, correlation and timeline analysis
- HTML/TXT report generation
- SHA-256 integrity verification and HMAC support
- Salted PBKDF2-HMAC-SHA256 password protection
- Streamlit SOC dashboard
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

Open the local Streamlit URL shown in the terminal.

## Dashboard workflow

1. Start the application.
2. Open **Dashboard → Ingest Logs**.
3. Upload `.log`, `.txt`, `.syslog`, `.json`, `.jsonl` or `.csv` files.
4. Click **Process Files**.
5. Review logs, alerts, incidents and timeline activity.
6. Generate an HTML or TXT investigation report.

Uploaded files are limited to 25 MB per file in the Streamlit UI to prevent accidental memory exhaustion. The underlying ingestion components can also be used programmatically for larger datasets.

## Detection engine

| Detector | Purpose |
|---|---|
| `BruteForceDetector` | Repeated authentication failures within a configurable sliding window |
| `FailedLoginDetector` | Repeated failures against an individual account |
| `KeywordDetector` | Security-relevant patterns such as SQL injection, XSS and privilege escalation |
| `ThreatIntelDetector` | Matches IPv4 addresses and CIDRs against offline intelligence |
| `AnomalyDetector` | Statistical deviations in log activity |

The brute-force detector triggers on the configured absolute threshold even when no statistical baseline exists; statistical analysis is used as additional context rather than suppressing the initial detection.

## Offline threat intelligence

The sample threat-intelligence file supports the repository's structured `suspicious_ips` format. The manager also accepts normalized `threat_ips` lists and validates IP/CIDR entries. Imported intelligence is stored locally and protected with a SHA-256 content digest.

## Security design

- Runtime SQLite databases, passwords, reports, logs and Python bytecode are excluded from Git.
- Passwords are stored using salted PBKDF2-HMAC-SHA256 rather than plaintext or unsalted hashes.
- Uploaded content is size-limited and decoded once before parsing.
- Detection alert IDs are deterministic where appropriate to improve deduplication.
- Raw log lines are retained for investigation traceability.

## Tests

```bash
pytest -q
```

GitHub Actions runs the regression suite on pushes to `main`/`stabilize-and-harden` and pull requests targeting `main`.

## Project structure

```text
offline-siem/
├── app.py
├── config.yaml
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

## Example programmatic workflow

```python
from src.detection import DetectionEngine
from src.parsers import registry
from src.storage import AlertStorage, LogStorage, SessionManager, get_database

content = open("samples/sample_logs.txt", encoding="utf-8").read()
logs = list(registry.parse_content(content, "text"))

db = get_database()
session_id = SessionManager(db).create_session(name="Analysis")
LogStorage(db).save_logs(session_id, logs)
alerts = DetectionEngine().detect_batch(logs)
AlertStorage(db).save_alerts(session_id, alerts)
```

## License

MIT License
