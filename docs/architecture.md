# SentinelX SOC — Architecture

## Vision
SentinelX is an offline-first Security Operations and Detection Platform. It unifies security-event ingestion, normalization, detection engineering, correlation, risk scoring, threat intelligence, investigation, threat hunting, incident response, and reporting in one analyst workflow.

## High-level flow

```text
Endpoints / Network / Files
          |
          v
     Collectors
          |
          v
 Event Normalization
          |
          v
   Event Store/Search
          |
          +----------------+
          |                |
          v                v
 Detection Engine     IOC Engine
          |                |
          +-------+--------+
                  v
          Correlation Engine
                  |
                  v
             Risk Engine
                  |
                  v
          Alerts / Incidents
                  |
       +----------+----------+
       |          |          |
       v          v          v
   Timeline    ATT&CK    Evidence
       |          |          |
       +----------+----------+
                  v
             SOC UI/API
          /       |       \
 Dashboard  Hunting  Reports
```

## Core modules

1. **Collectors** — Windows Event Logs, Sysmon, Linux authentication/system logs, web-server logs, firewall/network logs, and JSON/CSV uploads.
2. **Normalizer** — converts heterogeneous input into a common event schema.
3. **Event store** — stores normalized events and investigation metadata with an offline-first local database.
4. **Detection engine** — evaluates Sigma-style and native rules against normalized events.
5. **Correlation engine** — groups related detections into higher-level attack stories/incidents.
6. **Risk engine** — calculates severity, confidence, asset criticality, and overall incident risk.
7. **Threat intelligence** — maintains local IOC data and optionally supports enrichment adapters.
8. **MITRE ATT&CK mapping** — associates detections and incidents with tactics and techniques.
9. **Investigation** — timeline reconstruction, evidence, analyst notes, related events, and case management.
10. **Threat hunting** — analyst search/query workflow over historical normalized events.
11. **Reporting** — incident summaries, investigation reports, and exportable SOC metrics.

## Design principles

- Offline-first: core detection and investigation must work without external APIs.
- Modular: collectors, detections, enrichment providers, and storage adapters are replaceable.
- Explainable detections: every alert should show the rule, matched fields, reasoning, and ATT&CK mapping.
- Safe defaults: authentication, input validation, least privilege, and no destructive response actions by default.
- Testable: detection rules and parsers should have fixtures and automated tests.
- Analyst-first UX: prioritize triage, context, timelines, and clear evidence over decorative charts.

## Delivery phases

### Phase 1 — Foundation
FastAPI service, database models, common event schema, health checks, frontend shell, configuration, and tests.

### Phase 2 — SIEM
Log ingestion, parsing/normalization, event search, filtering, dashboard metrics, and sample datasets.

### Phase 3 — Detection engineering
Rule format, detection matcher, Sigma-compatible rules, alert lifecycle, ATT&CK mappings, and unit tests.

### Phase 4 — SOC workflow
Correlation, risk scoring, incidents/cases, analyst notes, evidence, and investigation timelines.

### Phase 5 — Threat intelligence
Local IOC store, hash/IP/domain/URL entities, enrichment interfaces, and IOC-to-event relationships.

### Phase 6 — Hunting and reporting
Threat-hunting queries, saved searches, ATT&CK coverage, incident reports, and SOC metrics.

### Phase 7 — Production quality
Docker deployment, CI, security checks, documentation, demo scenarios, performance improvements, and release packaging.
