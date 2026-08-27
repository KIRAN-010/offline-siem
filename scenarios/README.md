# SentinelX SOC Attack Simulation Lab

These scenarios contain synthetic defensive telemetry for validating SentinelX detections and investigation workflows. They are designed for local, authorized lab use and do not perform attacks themselves.

## SSH brute-force scenario

`ssh_bruteforce/events.jsonl` contains five failed SSH authentication events from one source IP within 80 seconds.

Expected SentinelX behavior:

1. JSONL events are ingested into the canonical event schema.
2. Built-in and YAML detections evaluate the events.
3. Rule `SX-SSH-001` reaches its threshold of five failures in five minutes.
4. The threshold engine emits one custom alert with the five supporting event IDs.
5. Correlation can group related alerts into an investigation case.

Example API ingestion:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/events \
  -H 'Content-Type: application/json' \
  --data "$(python -c 'import json; print(json.dumps([json.loads(line) for line in open("scenarios/ssh_bruteforce/events.jsonl")]))')"
```

For a cleaner repeatable run, use the scenario runner documented in `tools/run_scenario.py`.
