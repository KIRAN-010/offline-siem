# Presidency SOC - Security Analysis Platform

An offline security analysis and log management system for security operations center (SOC) workflows.

## Features

- **Log Ingestion**: Support for JSON, syslog, plain text, and CSV log formats
- **Normalization**: All logs converted to a common schema with raw line preservation
- **Detection Engine**: Rule-based and ML-based threat detection
  - Brute force attack detection
  - Failed login tracking
  - Suspicious keyword detection
  - Threat intelligence matching
  - Anomaly detection (IsolationForest)
- **Analytics**: Search, filter, group, correlate, and timeline analysis
- **Incident Management**: Create, track, and resolve security incidents
- **Reporting**: HTML and TXT reports with SHA-256 integrity verification
- **Security**: Input validation, password gating, report signing, safe file handling

## Installation

### Prerequisites

- Python 3.10+
- Windows/macOS/Linux

### Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Requirements

```
streamlit>=1.28.0
pyyaml>=6.0
scikit-learn>=1.0.0
pandas>=1.5.0
numpy>=1.21.0
```

## Usage

### Running the Application

```bash
# Start the Streamlit dashboard
streamlit run app.py
```

The application will be available at `http://localhost:8501`

### Using the CLI

```python
from src.ingestion import LogIngestor
from src.detection import DetectionEngine
from src.storage import (
    get_database, SessionManager, LogStorage,
    AlertStorage, IncidentManager
)
from src.analytics import TimelineBuilder
from src.reporting import ReportGenerator

# Initialize
db = get_database()
session_mgr = SessionManager(db)

# Create session
session_id = session_mgr.create_session(name="Analysis")

# Ingest logs
ingestor = LogIngestor()
logs = list(ingestor.ingest_file("samples/sample_logs.txt"))

# Save logs
log_storage = LogStorage(db)
log_storage.save_logs(session_id, logs)

# Run detection
engine = DetectionEngine()
alerts = engine.detect(iter(logs))

# Save alerts
alert_storage = AlertStorage(db)
alert_storage.save_alerts(session_id, alerts)

# Generate report
generator = ReportGenerator(db)
html_path = generator.generate_report(session_id, "html")
```

## Project Structure

```
presidency/
├── app.py                    # Main entry point
├── config.yaml               # Configuration
├── requirements.txt          # Dependencies
├── samples/                  # Sample data
│   ├── sample_logs.txt       # Plain text logs
│   ├── sample_logs.json      # JSON logs
│   ├── sample_logs.csv       # CSV logs
│   └── threat_intel.json     # Threat intelligence
├── src/
│   ├── schema.py             # Common log schema
│   ├── config.py             # Config loader
│   ├── logging_config.py    # Logging setup
│   ├── ingestion/            # Log ingestion
│   │   └── __init__.py       # LogIngestor
│   ├── parsers/              # Log parsers
│   │   ├── base.py           # BaseParser
│   │   ├── json_parser.py   # JSON parser
│   │   ├── syslog_parser.py # Syslog parser
│   │   ├── text_parser.py   # Text parser
│   │   ├── csv_parser.py    # CSV parser
│   │   └── __init__.py      # ParserRegistry
│   ├── detection/            # Detection engine
│   │   ├── alert.py          # Alert schema
│   │   ├── base.py           # BaseDetector
│   │   ├── brute_force.py   # BruteForceDetector
│   │   ├── failed_login.py   # FailedLoginDetector
│   │   ├── keyword_detector.py
│   │   ├── threat_intel.py   # ThreatIntelDetector
│   │   ├── anomaly.py        # AnomalyDetector
│   │   ├── engine.py         # DetectionEngine
│   │   └── __init__.py
│   ├── storage/              # Storage layer
│   │   ├── database.py       # SQLite manager
│   │   ├── session.py        # SessionManager
│   │   ├── file_tracker.py   # FileTracker
│   │   ├── log_storage.py    # LogStorage
│   │   ├── alert_storage.py  # AlertStorage
│   │   ├── incident.py       # IncidentManager
│   │   ├── audit.py          # AuditLogger
│   │   └── __init__.py
│   ├── analytics/            # Analytics
│   │   ├── search.py         # SearchEngine
│   │   ├── filter.py         # FilterBuilder
│   │   ├── grouping.py       # GroupingEngine
│   │   ├── correlation.py    # CorrelationEngine
│   │   ├── timeline.py       # TimelineBuilder
│   │   └── __init__.py
│   ├── reporting/            # Reporting
│   │   ├── base.py           # BaseReport
│   │   ├── html_report.py   # HTMLReport
│   │   ├── text_report.py   # TextReport
│   │   ├── generator.py     # ReportGenerator
│   │   └── __init__.py
│   ├── security/             # Security helpers
│   │   ├── validation.py    # InputValidator
│   │   ├── password_gate.py # PasswordGate
│   │   ├── signing.py       # ReportSigner
│   │   ├── file_handler.py  # SafeFileHandler
│   │   └── __init__.py
│   └── ui/                   # Streamlit UI
│       ├── dashboard.py     # Dashboard
│       └── __init__.py
└── data/                     # Data directory (created on first run)
```

## Demo Workflow

### 1. Start the Application

```bash
streamlit run app.py
```

### 2. Upload Sample Logs

1. Navigate to the Dashboard
2. Use the file uploader to upload `samples/sample_logs.txt`
3. Click "Process Files"

### 3. View Analysis Results

- **Dashboard**: See summary metrics (logs, alerts, incidents)
- **Alerts**: View detected threats with severity levels
- **Timeline**: See activity over time
- **Reports**: Generate HTML/TXT reports

### 4. Generate a Report

1. Go to the Reports page
2. Select format (HTML or TXT)
3. Click "Generate Report"
4. Report saved to `reports/` directory

## Detection Examples

The sample logs contain various attack patterns:

| Attack Type | Log Lines | Detection |
|-------------|-----------|-----------|
| Brute Force | 15 failed logins in 30s | BruteForceDetector |
| SQL Injection | "SQL injection attempt" | KeywordDetector |
| XSS Attack | "XSS attack detected" | KeywordDetector |
| Suspicious IP | 185.220.101.1 | ThreatIntelDetector |
| Anomaly | Unusual patterns | AnomalyDetector |

## Security Features

### Input Validation

```python
from src.security import InputValidator

InputValidator.validate_session_id(session_id)
InputValidator.validate_file_path(file_path)
InputValidator.sanitize_search_query(query)
```

### Password Gating

```python
from src.security import get_password_gate

gate = get_password_gate()
gate.set_password("secure123")
gate.verify("secure123")
```

### Report Signing

```python
from src.security import get_signer

signer = get_signer()
hash = signer.compute_content_hash(content)
signature = signer.sign_content(content)
```

## License

MIT License

## Support

For issues and questions, please refer to the project documentation.