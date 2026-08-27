from datetime import datetime, timezone, timedelta
from pathlib import Path

from app.rule_alerts import rule_alerts
from app.rule_engine import load_rule, load_rules
from app.schemas import SecurityEvent


RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "detections"


def test_ssh_threshold_generates_custom_alerts():
    rule = load_rule(RULES_DIR / "ssh_failed_logins.yml")
    base = datetime(2026, 8, 27, 10, 0, tzinfo=timezone.utc)
    events = [
        SecurityEvent(
            timestamp=base + timedelta(seconds=i),
            source="sshd",
            source_ip="192.0.2.10",
            severity="high",
            raw_data={"message": "Failed password for analyst"},
        )
        for i in range(5)
    ]
    alerts = rule_alerts(events, [rule])
    assert len(alerts) == 5
    assert all(alert.alert_type.value == "CUSTOM" for alert in alerts)
    assert all(alert.metadata["rule_id"] == "SX-SSH-001" for alert in alerts)


def test_disabled_rules_are_not_loaded():
    rules = load_rules(RULES_DIR)
    assert all(rule.enabled for rule in rules)
