import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query

from .alert_store import save_alerts
from .db import get_connection
from .detection_bridge import detect_events
from .event_store import save_events
from .schemas import SecurityEvent

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", status_code=201)
def ingest_events(events: list[SecurityEvent]) -> dict[str, Any]:
    accepted = save_events(events)
    detected = []
    detection_error: str | None = None
    try:
        detected = detect_events(events)
        save_alerts(detected)
    except Exception as exc:
        detection_error = str(exc)

    result: dict[str, Any] = {
        "accepted": accepted,
        "received": len(events),
        "alerts_generated": len(detected),
    }
    if detection_error:
        result["detection_error"] = detection_error
    return result


@router.get("")
def list_events(
    source: str | None = None,
    severity: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (("source", source), ("severity", severity), ("username", username), ("source_ip", source_ip)):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    if start:
        clauses.append("timestamp >= ?")
        params.append(start.isoformat())
    if end:
        clauses.append("timestamp <= ?")
        params.append(end.isoformat())

    query = "SELECT * FROM events"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        rows = [dict(row) for row in conn.execute(query, params).fetchall()]
    for row in rows:
        row["raw_data"] = json.loads(row["raw_data"])
    return {"count": len(rows), "events": rows}
