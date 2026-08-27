from datetime import datetime, timezone, timedelta
from pathlib import Path

from app.rule_alerts import rule_alerts
from app.rule_engine import load_rule, load_rules
from app.schemas import SecurityEvent


RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "detections"


def _events(count: int) -> list[SecurityEvent]:
    rule_time = datetime(2026, 8, 27, 10, 0, tzinfo=timezone.utc)
    return [
        SecurityEvent(
            timestamp=rule_time + timedelta(seconds=i),
            source="sshd",
            username="analyst",
            source_ip="192.0.2.10",
            severity="high",
            raw_data={"message": "Failed password for analyst"},
        )
        for i in range(count)
    ]


def test_ssh_threshold_generates_one_custom_alert_with_evidence():
    rule = load_rule(RULES_DIR / "ssh_failed_logins.yml")
    alerts = rule_alerts(_events(5), [rule])
    assert len(alerts) == 1
    assert alerts[0].alert_type.value == "CUSTOM"
    assert alerts[0].metadata["rule_id"] == "SX-SSH-001"
    assert len(alerts[0].source_logs) == 5


def test_ssh_threshold_does_not_alert_before_count():
    rule = load_rule(RULES_DIR / "ssh_failed_logins.yml")
    alerts = rule_alerts(_events(4), [rule])
    assert alerts == []


def test_disabled_rules_are_not_loaded():
    rules = load_rules(RULES_DIR)
    assert all(rule.enabled for rule in rules)
