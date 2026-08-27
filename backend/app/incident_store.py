import hashlib
import json
from typing import Any

from .db import get_connection


def _severity_rank(value: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value.upper(), 0)


def create_incident(title: str, alert_uids: list[str], indicators: dict[str, Any], summary: str, db_path=None) -> dict[str, Any]:
    canonical = json.dumps(sorted(alert_uids), separators=(",", ":"))
    incident_uid = "INC-" + hashlib.sha256(canonical.encode()).hexdigest()[:12]
    with get_connection(db_path) as conn:
        existing = conn.execute("SELECT * FROM incidents WHERE incident_uid = ?", (incident_uid,)).fetchone()
        if existing:
            row = dict(existing)
        else:
            severities = conn.execute(
                f"SELECT severity FROM alerts WHERE alert_uid IN ({','.join('?' for _ in alert_uids)})",
                alert_uids,
            ).fetchall() if alert_uids else []
            severity = max((row["severity"] for row in severities), key=_severity_rank, default="LOW")
            conn.execute(
                """INSERT INTO incidents (incident_uid,title,severity,status,alert_uids,indicators,summary)
                VALUES (?,?,?,?,?,?,?)""",
                (incident_uid, title, severity, "open", json.dumps(sorted(alert_uids)), json.dumps(indicators), summary),
            )
            row = dict(conn.execute("SELECT * FROM incidents WHERE incident_uid = ?", (incident_uid,)).fetchone())
    row["alert_uids"] = json.loads(row["alert_uids"])
    row["indicators"] = json.loads(row["indicators"])
    return row


def list_incidents(status: str | None = None, severity: str | None = None, limit: int = 100, db_path=None) -> list[dict[str, Any]]:
    clauses = []
    params: list[Any] = []
    if status:
        clauses.append("status = ?")
        params.append(status)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    query = "SELECT * FROM incidents"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with get_connection(db_path) as conn:
        rows = [dict(row) for row in conn.execute(query, params).fetchall()]
    for row in rows:
        row["alert_uids"] = json.loads(row["alert_uids"])
        row["indicators"] = json.loads(row["indicators"])
    return rows
