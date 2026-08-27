from datetime import datetime
from typing import Any

from src.detection.alert import Alert, AlertSeverity, AlertType

from .rule_engine import DetectionRule, detect
from .schemas import SecurityEvent


def rule_alerts(events: list[SecurityEvent], rules: list[DetectionRule]) -> list[Alert]:
    payloads = [event.model_dump(mode="json") for event in events]
    alerts: list[Alert] = []
    for match in detect(payloads, rules):
        event = match["event"]
        severity = AlertSeverity(match["severity"].upper())
        timestamp = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
        indicators: dict[str, Any] = {}
        for key in ("source_ip", "destination_ip", "username", "host"):
            if event.get(key):
                indicators[key] = event[key]
        alert_id = f"{match['rule_id']}:{event.get('event_uid', event.get('timestamp'))}"
        alerts.append(
            Alert(
                id=alert_id,
                alert_type=AlertType.CUSTOM,
                severity=severity,
                reason=match["title"],
                description=match["description"],
                timestamp=timestamp,
                source_logs=[str(event.get("event_uid", event.get("timestamp", "")))],
                indicators=indicators,
                matched_pattern=match["rule_id"],
                confidence=1.0,
                metadata={"rule_id": match["rule_id"], "tags": match["tags"]},
            )
        )
    return alerts
