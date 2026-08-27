from typing import Any

from fastapi import APIRouter, Query

from .alert_store import list_alerts

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("")
def get_alerts(
    status: str | None = None,
    severity: str | None = None,
    alert_type: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    alerts = list_alerts(status=status, severity=severity, alert_type=alert_type, limit=limit)
    return {"count": len(alerts), "alerts": alerts}
