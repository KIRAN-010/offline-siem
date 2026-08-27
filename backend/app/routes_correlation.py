from typing import Any

from fastapi import APIRouter, Query

from .correlation import correlate_alerts, create_correlated_incidents

router = APIRouter(prefix="/api/v1/correlation", tags=["correlation"])


@router.get("/preview")
def preview_correlations(
    window_minutes: int = Query(default=15, ge=1, le=1440),
    min_alerts: int = Query(default=2, ge=2, le=20),
) -> dict[str, Any]:
    groups = correlate_alerts(window_minutes=window_minutes, min_alerts=min_alerts)
    return {"count": len(groups), "groups": groups}


@router.post("/run")
def run_correlation(
    window_minutes: int = Query(default=15, ge=1, le=1440),
    min_alerts: int = Query(default=2, ge=2, le=20),
) -> dict[str, Any]:
    incidents = create_correlated_incidents(window_minutes=window_minutes, min_alerts=min_alerts)
    return {"created": len(incidents), "incidents": incidents}
