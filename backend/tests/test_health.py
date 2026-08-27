from fastapi.testclient import TestClient

from app.main import APP_VERSION, app
import app.routes_events as routes_events
import app.routes_alerts as routes_alerts
import app.routes_incidents as routes_incidents


def test_app_is_created():
    assert app is not None
    assert APP_VERSION == "0.9.1"


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
    assert response.json()["accepted"] == 1
    assert response.json()["received"] == 1
    assert response.json()["alerts_generated"] == 0
    assert captured["events"] is not None
    assert captured["alerts"] == []


def test_alert_endpoint(monkeypatch):
    monkeypatch.setattr(
        routes_alerts,
        "list_alerts",
        lambda **kwargs: [{"alert_uid": "TEST-1", "severity": "HIGH"}],
    )
    response = TestClient(app).get("/api/v1/alerts", params={"severity": "HIGH"})
    assert response.status_code == 200
    assert response.json() == {
        "count": 1,
        "alerts": [{"alert_uid": "TEST-1", "severity": "HIGH"}],
    }


def test_alert_status_update(monkeypatch):
    monkeypatch.setattr(routes_alerts, "update_alert_status", lambda alert_uid, status: status == "acknowledged")
    response = TestClient(app).patch(
        "/api/v1/alerts/TEST-1/status",
        json={"status": "acknowledged"},
    )
    assert response.status_code == 200
    assert response.json() == {"alert_uid": "TEST-1", "status": "acknowledged"}


def test_alert_status_rejects_invalid_value(monkeypatch):
    def reject(alert_uid, status):
        raise ValueError("Unsupported alert status: nope")

    monkeypatch.setattr(routes_alerts, "update_alert_status", reject)
    response = TestClient(app).patch(
        "/api/v1/alerts/TEST-1/status",
        json={"status": "nope"},
    )
    assert response.status_code == 400


def test_dashboard_summary(monkeypatch):
    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, query):
            class Row:
                def fetchone(self):
                    return (0,)

                def fetchall(self):
                    return []

            return Row()

    monkeypatch.setattr("app.routes_dashboard.get_connection", lambda: FakeConnection())
    response = TestClient(app).get("/api/v1/dashboard/summary")
    assert response.status_code == 200
    assert response.json()["events"] == 0
    assert response.json()["alerts"] == 0


def test_incident_endpoint(monkeypatch):
    monkeypatch.setattr(
        routes_incidents,
        "create_incident",
        lambda **kwargs: {"incident_uid": "INC-TEST", "severity": "HIGH", "title": kwargs["title"]},
    )
    response = TestClient(app).post(
        "/api/v1/incidents",
        json={
            "title": "Suspicious authentication activity",
            "alert_uids": ["ALERT-1", "ALERT-2"],
            "summary": "Related authentication detections",
        },
    )
    assert response.status_code == 201
    assert response.json()["incident_uid"] == "INC-TEST"
