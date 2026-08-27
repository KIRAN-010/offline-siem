from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


SAMPLE_EVENT = {
    "timestamp": "2026-08-27T08:00:00+00:00",
    "source": "sshd",
    "host": "server-01",
    "username": "analyst",
    "source_ip": "10.10.10.5",
    "destination_ip": "10.10.10.10",
    "event_id": "SSH-FAIL",
    "process": "sshd",
    "command": None,
    "severity": "high",
    "raw_data": {"message": "Failed password for analyst"},
}


def test_event_ingest_and_query(tmp_path, monkeypatch):
    from app import db
    from app import event_store

    test_db = tmp_path / "sentinelx-test.db"
    monkeypatch.setattr(db, "DEFAULT_DB_PATH", test_db)
    monkeypatch.setattr(event_store, "DEFAULT_DB_PATH", test_db)

    ingest = client.post("/api/v1/events", json=[SAMPLE_EVENT])
    assert ingest.status_code == 201
    assert ingest.json() == {"accepted": 1, "received": 1}

    duplicate = client.post("/api/v1/events", json=[SAMPLE_EVENT])
    assert duplicate.status_code == 201
    assert duplicate.json() == {"accepted": 0, "received": 1}

    result = client.get(
        "/api/v1/events",
        params={"severity": "high", "source_ip": "10.10.10.5", "limit": 10},
    )
    assert result.status_code == 200
    body = result.json()
    assert body["count"] == 1
    assert body["events"][0]["event_uid"]
    assert body["events"][0]["raw_data"]["message"] == "Failed password for analyst"
