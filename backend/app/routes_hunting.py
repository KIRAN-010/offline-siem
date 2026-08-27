from typing import Any

from fastapi import APIRouter, Query

from .db import get_connection

router = APIRouter(prefix="/api/v1/hunting", tags=["hunting"])


@router.get("/search")
def hunt(
    q: str | None = Query(default=None, max_length=300),
    source: str | None = Query(default=None, max_length=100),
    username: str | None = Query(default=None, max_length=255),
    source_ip: str | None = Query(default=None, max_length=45),
    severity: str | None = Query(default=None, max_length=20),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict[str, Any]:
    """Search normalized security events using parameterized filters only."""
    clauses: list[str] = []
    params: list[Any] = []

    if q:
        clauses.append("(message LIKE ? OR raw_data LIKE ? OR process LIKE ? OR command LIKE ?)")
        term = f"%{q}%"
        params.extend([term, term, term, term])
    for column, value in (
        ("source", source),
        ("username", username),
        ("source_ip", source_ip),
        ("severity", severity),
    ):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)

    query = "SELECT * FROM events"
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    with get_connection() as conn:
        rows = [dict(row) for row in conn.execute(query, params).fetchall()]

        counts = conn.execute(
            "SELECT severity, COUNT(*) AS count FROM events" +
            ((" WHERE " + " AND ".join(clauses)) if clauses else "") +
            " GROUP BY severity ORDER BY count DESC",
            params[:-1],
        ).fetchall()

    return {
        "count": len(rows),
        "events": rows,
        "summary": {row["severity"]: row["count"] for row in counts},
    }
