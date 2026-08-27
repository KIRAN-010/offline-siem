from datetime import datetime, timezone

from app.attack_map import map_incident_to_attack
from app.risk_engine import calculate_incident_risk


def test_risk_scoring_is_bounded_and_explainable():
    result = calculate_incident_risk(
        [
            {
                "alert_type": "FAILED_LOGIN",
                "severity": "HIGH",
                "confidence": 0.9,
                "indicators": {"username": "admin", "source_ip": "192.0.2.10"},
            },
            {
                "alert_type": "SUSPICIOUS_IP",
                "severity": "MEDIUM",
                "confidence": 1.0,
                "indicators": {"source_ip": "192.0.2.10", "ip_reputation": "malicious"},
            },
        ]
    )
    assert 0 <= result["score"] <= 100
    assert result["level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result["factors"]["alert_count"] == 2
    assert result["factors"]["distinct_alert_types"] == 2


def test_attack_mapping_is_deduplicated():
    techniques = map_incident_to_attack(
        [
            {"alert_type": "FAILED_LOGIN"},
            {"alert_type": "BRUTE_FORCE"},
            {"alert_type": "SUSPICIOUS_KEYWORD"},
        ]
    )
    ids = [item["technique_id"] for item in techniques]
    assert ids.count("T1110") == 1
    assert "T1059" in ids


def test_correlation_groups_shared_indicator(monkeypatch):
    import app.correlation as correlation

    ts = "2026-08-27T10:00:00+00:00"
    alerts = [
        {
            "alert_uid": "A1",
            "timestamp": ts,
            "alert_type": "FAILED_LOGIN",
            "severity": "HIGH",
            "confidence": 0.9,
            "indicators": {"source_ip": "192.0.2.10"},
        },
        {
            "alert_uid": "A2",
            "timestamp": "2026-08-27T10:05:00+00:00",
            "alert_type": "SUSPICIOUS_IP",
            "severity": "MEDIUM",
            "confidence": 0.8,
            "indicators": {"source_ip": "192.0.2.10"},
        },
    ]
    monkeypatch.setattr(correlation, "list_alerts", lambda **kwargs: alerts)
    groups = correlation.correlate_alerts(window_minutes=15, min_alerts=2)
    assert groups
    assert set(groups[0]["alert_uids"]) == {"A1", "A2"}
    assert groups[0]["correlation_key"] == "source_ip:192.0.2.10"
