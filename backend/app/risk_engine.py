from __future__ import annotations

from typing import Any


SEVERITY_WEIGHT = {"LOW": 25, "MEDIUM": 50, "HIGH": 75, "CRITICAL": 100}


def calculate_alert_risk(alert: dict[str, Any]) -> int:
    """Calculate an explainable 0-100 risk score for a single alert."""
    severity = str(alert.get("severity", "LOW")).upper()
    base = SEVERITY_WEIGHT.get(severity, 25)
    confidence = max(0.0, min(float(alert.get("confidence", 1.0)), 1.0))
    indicators = alert.get("indicators") or {}
    boost = 0
    if indicators.get("source_ip"):
        boost += 5
    if indicators.get("username"):
        boost += 5
    if indicators.get("ip_reputation") in {"malicious", "high_risk"}:
        boost += 15
    if str(indicators.get("privileged", "")).lower() == "true":
        boost += 10
    return max(0, min(100, round(base * confidence + boost)))


def calculate_incident_risk(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate alert risk with correlation breadth into an explainable score."""
    if not alerts:
        return {"score": 0, "level": "LOW", "factors": {}}

    scores = [calculate_alert_risk(alert) for alert in alerts]
    max_score = max(scores)
    breadth_bonus = min(20, max(0, len({a.get('alert_type') for a in alerts}) - 1) * 5)
    score = min(100, max_score + breadth_bonus)

    if score >= 85:
        level = "CRITICAL"
    elif score >= 65:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    factors = {
        "highest_alert_risk": max_score,
        "distinct_alert_types": len({a.get("alert_type") for a in alerts}),
        "correlation_breadth_bonus": breadth_bonus,
        "alert_count": len(alerts),
    }
    return {"score": score, "level": level, "factors": factors}
