from pathlib import Path

from app.rule_engine import load_rule, load_rules, rule_matches


RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "detections"


def test_loads_detection_rules():
    rules = load_rules(RULES_DIR)
    ids = {rule.id for rule in rules}
    assert {"SX-SSH-001", "SX-WIN-001", "SX-WEB-001"} <= ids


def test_ssh_rule_matches_case_insensitively():
    rule = load_rule(RULES_DIR / "ssh_failed_logins.yml")
    event = {"message": "Failed Password for admin from 192.0.2.5"}
    assert rule_matches(rule, event)


def test_ssh_rule_does_not_match_unrelated_event():
    rule = load_rule(RULES_DIR / "ssh_failed_logins.yml")
    event = {"message": "Accepted publickey for admin"}
    assert not rule_matches(rule, event)


def test_powershell_rule_matches_command():
    rule = load_rule(RULES_DIR / "powershell_encoded.yml")
    event = {"command": "powershell.exe -EncodedCommand SQBFAFg="}
    assert rule_matches(rule, event)


def test_web_rule_matches_nested_raw_data():
    rule = load_rule(RULES_DIR / "web_attack.yml")
    event = {"raw_data": {"message": "GET /?q=UNION SELECT password FROM users"}}
    assert rule_matches(rule, event)
