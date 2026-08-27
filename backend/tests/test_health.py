from fastapi.testclient import TestClient

from app.main import APP_VERSION, app
import app.routes_events as routes_events


def test_app_is_created():
    assert app is not None
    assert APP_VERSION == "0.3.0"


def test_health():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_event_ingest_runs_detection(monkeypatch):
    captured = {"events": None, "alerts": None}

    def fake_save_events(events):
        captured["events"] = events
        return len(events)

    def fake_detect_events(events):
        captured["events"] = events
        return []

    def fake_save_alerts(alerts):
        captured["alerts"] = alerts
        return len(alerts)

    monkeypatch.setattr(routes_events, "save_events", fake_save_events)
    monkeypatch.setattr(routes_events, "detect_events", fake_detect_events)
    monkeypatch.setattr(routes_events, "save_alerts", fake_save_alerts)

    response = TestClient(app).post(
        "/api/v1/events",
        json=[
            {
                "timestamp": "2026-08-27T10:00:00Z",
                "source": "test",
                "username": "admin",
                "source_ip": "192.0.2.10",
                "severity": "warning",
                "raw_data": {"message": "login failed for admin"},
            }
        ],
    )

    assert response.status_code == 201
    assert response.json() == {"accepted": 1, "received": 1, "alerts_generated": 0}
    assert captured["events"] is not None
    assert captured["alerts"] == []


def test_alert_endpoint(monkeypatch):
    monkeypatch.setattr(
        "app.routes_alerts.list_alerts",
        lambda **kwargs: [{"alert_uid": "TEST-1", "severity": "HIGH"}],
    )
    response = TestClient(app).get("/api/v1/alerts", params={"severity": "HIGH"})
    assert response.status_code == 200
    assert response.json() == {
        "count": 1,
        "alerts": [{"alert_uid": "TEST-1", "severity": "HIGH"}],
    }
