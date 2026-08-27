from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .alert_store import list_alerts, update_alert_status

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


class AlertStatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=30)


@router.get("")
def get_alerts(
    status: str | None = None,
    severity: str | None = None,
    alert_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    alerts = list_alerts(status=status, severity=severity, alert_type=alert_type, limit=limit)
    return {"count": len(alerts), "alerts": alerts}


@router.patch("/{alert_uid}/status")
def set_alert_status(alert_uid: str, payload: AlertStatusUpdate) -> dict[str, Any]:
    try:
        updated = update_alert_status(alert_uid, payload.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert_uid": alert_uid, "status": payload.status}
