import hashlib
import json
from pathlib import Path
from typing import Iterable

from .db import DEFAULT_DB_PATH, get_connection
from .schemas import SecurityEvent


def event_uid(event: SecurityEvent) -> str:
    """Return a deterministic SHA-256 identifier for an event."""
    payload = event.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def save_events(events: Iterable[SecurityEvent], db_path: Path | None = None) -> int:
    """Persist events and return the number of newly inserted rows."""
    rows = []
    for event in events:
        rows.append(
            (
                event_uid(event),
                event.timestamp.isoformat(),
                event.source,
                event.host,
                event.username,
                event.source_ip,
                event.destination_ip,
                event.event_id,
                event.process,
                event.command,
                event.severity,
                json.dumps(event.raw_data, sort_keys=True),
            )
        )

    if not rows:
        return 0

    with get_connection(db_path or DEFAULT_DB_PATH) as conn:
        before = conn.total_changes
        conn.executemany(
            """INSERT OR IGNORE INTO events
            (event_uid,timestamp,source,host,username,source_ip,destination_ip,
             event_id,process,command,severity,raw_data)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        return conn.total_changes - before
