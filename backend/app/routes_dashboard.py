from typing import Any

from fastapi import APIRouter

from .db import get_connection

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary() -> dict[str, Any]:
    with get_connection() as conn:
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        new_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'new'").fetchone()[0]
        severity_rows = conn.execute(
            "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity"
        ).fetchall()
        type_rows = conn.execute(
            "SELECT alert_type, COUNT(*) AS count FROM alerts GROUP BY alert_type"
        ).fetchall()

    return {
        "events": event_count,
        "alerts": alert_count,
        "new_alerts": new_alerts,
        "alerts_by_severity": {row["severity"]: row["count"] for row in severity_rows},
        "alerts_by_type": {row["alert_type"]: row["count"] for row in type_rows},
    }
