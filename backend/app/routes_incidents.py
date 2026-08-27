from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .incident_store import create_incident, list_incidents

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    alert_uids: list[str] = Field(min_length=1, max_length=100)
    indicators: dict[str, Any] = Field(default_factory=dict)
    summary: str = Field(default="", max_length=4000)


@router.post("", status_code=201)
def create_case(payload: IncidentCreate) -> dict[str, Any]:
    incident = create_incident(
        title=payload.title,
        alert_uids=payload.alert_uids,
        indicators=payload.indicators,
        summary=payload.summary,
    )
    return incident


@router.get("")
def get_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    incidents = list_incidents(status=status, severity=severity, limit=limit)
    return {"count": len(incidents), "incidents": incidents}
