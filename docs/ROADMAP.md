# SentinelX implementation status

## Available and tested

- [x] FastAPI service and health/readiness endpoints
- [x] SQLite schema, canonical UTC events and deduplication
- [x] JSON/JSONL/CSV/text file imports through the console and API
- [x] Linux/syslog/text parsing and structured event field mapping
- [x] Event search, threat hunting and saved searches
- [x] Local detection engine, YAML rule loading/matching and fixtures
- [x] Alert lifecycle, correlation, incident management and risk scoring
- [x] Basic MITRE ATT&CK technique mappings
- [x] Analyst notes and explicit event evidence links
- [x] Investigation timelines and JSON/HTML/text case reports
- [x] Offline IP/CIDR intelligence matching
- [x] React analyst controls for ingestion, triage and investigation
- [x] Streamlit interface
- [x] Reproducible frontend dependency lockfile
- [x] Python and frontend interaction tests
- [x] Docker configuration and GitHub Actions validation
- [x] Synthetic brute-force scenario and deployment instructions

## Optional future expansion

These are beyond the supported local workflow, rather than prerequisites for running it:

- Full Sigma specification and specialized Windows EVTX parsing
- Large-scale continuous ingestion across API batches
- Domain/hash/URL intelligence providers and enrichment adapters
- Advanced hunting query language and complete ATT&CK coverage matrix
- Authentication, roles and multi-user audit attribution
- Additional real-world telemetry datasets and performance benchmarks
- Packaged offline dependency bundles and signed release artifacts

Docker smoke testing runs in GitHub Actions; local verification requires Docker to be installed. JSON documents use document parsing; JSONL/text and CSV support streaming ingestion. API imports are bounded to 2 MiB and 10,000 events.
