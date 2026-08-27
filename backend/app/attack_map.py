from __future__ import annotations

from typing import Any

ALERT_ATTACK_MAP: dict[str, list[dict[str, str]]] = {
    "BRUTE_FORCE": [
        {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"}
    ],
    "FAILED_LOGIN": [
        {"tactic": "Credential Access", "technique_id": "T1110", "technique": "Brute Force"}
    ],
    "SUSPICIOUS_KEYWORD": [
        {"tactic": "Execution", "technique_id": "T1059", "technique": "Command and Scripting Interpreter"}
    ],
    "SUSPICIOUS_IP": [
        {"tactic": "Command and Control", "technique_id": "T1071", "technique": "Application Layer Protocol"}
    ],
    "ANOMALY": [],
    "CUSTOM": [],
}


def map_alert_to_attack(alert: dict[str, Any]) -> list[dict[str, str]]:
    """Return defensive MITRE ATT&CK context for a persisted alert."""
    return ALERT_ATTACK_MAP.get(str(alert.get("alert_type", "CUSTOM")).upper(), [])


def map_incident_to_attack(alerts: list[dict[str, Any]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    techniques: list[dict[str, str]] = []
    for alert in alerts:
        for technique in map_alert_to_attack(alert):
            key = (technique["technique_id"], technique["tactic"])
            if key not in seen:
                seen.add(key)
                techniques.append(technique)
    return sorted(techniques, key=lambda item: item["technique_id"])
