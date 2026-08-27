import json
from typing import Any, Iterable

from src.detection.alert import Alert

from .db import get_connection


def save_alerts(alerts: Iterable[Alert], db_path=None) -> int:
    rows = []
    for alert in alerts:
        rows.append(
            (
                alert.id,
                alert.alert_type.value,
                alert.severity.value,
                alert.reason,
                alert.description,
                alert.timestamp.isoformat(),
                json.dumps(alert.source_logs),
                json.dumps(alert.indicators, sort_keys=True),
                alert.matched_pattern,
                float(alert.confidence),
                json.dumps(alert.metadata, sort_keys=True),
            )
        )
    if not rows:
        return 0
    with get_connection(db_path) as conn:
        before = conn.total_changes
        conn.executemany(
            """INSERT OR IGNORE INTO alerts
            (alert_uid, alert_type, severity, reason, description, timestamp,
             source_logs, indicators, matched_pattern, confidence, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        return conn.total_changes - before


def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    alert_type: str | None = None,
    limit: int = 100,
    db_path=None,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (("status", status), ("severity", severity), ("alert_type", alert_type)):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    query = "SELECT * FROM alerts"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_connection(db_path) as conn:
        rows = [dict(row) for row in conn.execute(query, params).fetchall()]
    for row in rows:
        row["source_logs"] = json.loads(row["source_logs"])
        row["indicators"] = json.loads(row["indicators"])
        row["metadata"] = json.loads(row["metadata"])
    return rows


def update_alert_status(alert_uid: str, status: str, db_path=None) -> bool:
    allowed = {"new", "acknowledged", "resolved", "false_positive"}
    if status not in allowed:
        raise ValueError(f"Unsupported alert status: {status}")
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "UPDATE alerts SET status = ? WHERE alert_uid = ?",
            (status, alert_uid),
        )
        return cursor.rowcount == 1
