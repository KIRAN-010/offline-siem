from pathlib import Path

from src.detection import DetectionEngine
from src.ingestion import LogIngestor


def test_detection_engine_finds_failed_login_activity():
    sample = Path(__file__).with_name("test_sample.txt")
    logs = list(LogIngestor().ingest_file(sample, format="text"))

    alerts = DetectionEngine(
        enable_anomaly=False,
        enable_threat_intel=False,
        enable_keyword=True,
        enable_brute_force=True,
        enable_failed_login=True,
    ).detect_batch(logs)

    assert alerts
    assert any("login" in alert.reason.lower() or "brute" in alert.reason.lower() for alert in alerts)


def test_detection_summary_is_consistent():
    sample = Path(__file__).with_name("test_sample.txt")
    logs = list(LogIngestor().ingest_file(sample, format="text"))
    engine = DetectionEngine(
        enable_anomaly=False,
        enable_threat_intel=False,
    )

    alerts = engine.detect_batch(logs)
    summary = engine.get_alert_summary(alerts)

    assert summary["total"] == len(alerts)
    assert sum(summary["by_severity"].values()) == len(alerts)
    assert sum(summary["by_type"].values()) == len(alerts)
