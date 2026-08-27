from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .incident_store import create_incident, list_incidents
from .db import get_connection

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    alert_uids: list[str] = Field(min_length=1, max_length=100)
    indicators: dict[str, Any] = Field(default_factory=dict)
    summary: str = Field(default="", max_length=4000)


class IncidentStatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=30)


@router.post("", status_code=201)
def create_case(payload: IncidentCreate) -> dict[str, Any]:
    return create_incident(
        title=payload.title,
        alert_uids=payload.alert_uids,
        indicators=payload.indicators,
        summary=payload.summary,
    )


@router.get("")
def get_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    incidents = list_incidents(status=status, severity=severity, limit=limit)
    return {"count": len(incidents), "incidents": incidents}


@router.get("/{incident_uid}")
def get_incident(incident_uid: str) -> dict[str, Any]:
    for incident in list_incidents(limit=1000):
        if incident["incident_uid"] == incident_uid:
            return incident
    raise HTTPException(status_code=404, detail="Incident not found")


@router.patch("/{incident_uid}/status")
def set_incident_status(incident_uid: str, payload: IncidentStatusUpdate) -> dict[str, str]:
    allowed = {"open", "investigating", "contained", "resolved", "closed"}
    if payload.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Unsupported incident status: {payload.status}")
    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE incident_uid = ?",
            (payload.status, incident_uid),
        )
    if cursor.rowcount != 1:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"incident_uid": incident_uid, "status": payload.status}
