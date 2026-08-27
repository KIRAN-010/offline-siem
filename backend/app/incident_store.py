import hashlib
import json
from typing import Any

from .attack_map import map_incident_to_attack
from .db import get_connection
from .risk_engine import calculate_incident_risk


def _severity_rank(value: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(value.upper(), 0)


def _get_alerts(conn, alert_uids: list[str]) -> list[dict[str, Any]]:
    if not alert_uids:
        return []
    placeholders = ",".join("?" for _ in alert_uids)
    rows = [
        dict(row)
        for row in conn.execute(
            f"SELECT * FROM alerts WHERE alert_uid IN ({placeholders})",
            alert_uids,
        ).fetchall()
    ]
    for row in rows:
        row["indicators"] = json.loads(row["indicators"])
        row["metadata"] = json.loads(row["metadata"])
    return rows


def create_incident(
    title: str,
    alert_uids: list[str],
    indicators: dict[str, Any],
    summary: str,
    db_path=None,
) -> dict[str, Any]:
    canonical = json.dumps(sorted(set(alert_uids)), separators=(",", ":"))
    incident_uid = "INC-" + hashlib.sha256(canonical.encode()).hexdigest()[:12]
    with get_connection(db_path) as conn:
        existing = conn.execute(
            "SELECT * FROM incidents WHERE incident_uid = ?", (incident_uid,)
        ).fetchone()
        if existing:
            row = dict(existing)
        else:
            alerts = _get_alerts(conn, alert_uids)
            severity = max(
                (alert["severity"] for alert in alerts),
                key=_severity_rank,
                default="LOW",
            )
            risk = calculate_incident_risk(alerts)
            techniques = map_incident_to_attack(alerts)
            conn.execute(
                """INSERT INTO incidents
                (incident_uid,title,severity,status,alert_uids,indicators,summary,
                 risk_score,risk_level,attack_techniques)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    incident_uid,
                    title,
                    severity,
                    "open",
                    json.dumps(sorted(set(alert_uids))),
                    json.dumps(indicators, sort_keys=True),
                    summary,
                    risk["score"],
                    risk["level"],
                    json.dumps(techniques, sort_keys=True),
                ),
            )
            row = dict(
                conn.execute(
                    "SELECT * FROM incidents WHERE incident_uid = ?", (incident_uid,)
                ).fetchone()
            )
    row["alert_uids"] = json.loads(row["alert_uids"])
    row["indicators"] = json.loads(row["indicators"])
    row["attack_techniques"] = json.loads(row.get("attack_techniques", "[]"))
    return row


def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 100,
    db_path=None,
) -> list[dict[str, Any]]:
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
        row["attack_techniques"] = json.loads(row.get("attack_techniques", "[]"))
    return rows
