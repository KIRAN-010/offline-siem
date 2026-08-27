import json
from typing import Any

from fastapi import APIRouter, HTTPException

from .attack_map import map_incident_to_attack
from .db import get_connection
from .incident_store import list_incidents

router = APIRouter(prefix="/api/v1/investigation", tags=["investigation"])


def _get_incident(incident_uid: str) -> dict[str, Any]:
    incidents = list_incidents(limit=1000)
    for incident in incidents:
        if incident["incident_uid"] == incident_uid:
            return incident
    raise HTTPException(status_code=404, detail="Incident not found")


@router.get("/{incident_uid}/timeline")
def incident_timeline(incident_uid: str) -> dict[str, Any]:
    incident = _get_incident(incident_uid)
    alert_uids = incident.get("alert_uids", [])

    with get_connection() as conn:
        alerts = [
            dict(row)
            for row in conn.execute(
                f"SELECT * FROM alerts WHERE alert_uid IN ({','.join('?' for _ in alert_uids)}) ORDER BY timestamp ASC",
                alert_uids,
            ).fetchall()
        ] if alert_uids else []
        for row in alerts:
            row["indicators"] = json.loads(row["indicators"])
            row["metadata"] = json.loads(row["metadata"])

        indicator_values = set()
        for alert in alerts:
            for field in ("source_ip", "username", "host"):
                value = alert["indicators"].get(field)
                if value:
                    indicator_values.add((field, str(value)))

        clauses = []
        params: list[Any] = []
        for field, value in indicator_values:
            clauses.append(f"{field} = ?")
            params.append(value)
        events = []
        if clauses:
            rows = conn.execute(
                "SELECT * FROM events WHERE " + " OR ".join(clauses) + " ORDER BY timestamp ASC LIMIT 1000",
                params,
            ).fetchall()
            events = [dict(row) for row in rows]
            for event in events:
                event["raw_data"] = json.loads(event["raw_data"])

    timeline = [
        {"kind": "event", "timestamp": e["timestamp"], "data": e} for e in events
    ] + [
        {"kind": "alert", "timestamp": a["timestamp"], "data": a} for a in alerts
    ]
    timeline.sort(key=lambda item: item["timestamp"])

    return {
        "incident": incident,
        "timeline": timeline,
        "mitre_attack": map_incident_to_attack(alerts),
    }
