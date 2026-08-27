import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "sentinelx.db"


def init_db(db_path: Path | None = None) -> None:
    """Create the local SentinelX database schema when needed."""
    path = db_path or DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_uid TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                host TEXT,
                username TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                event_id TEXT,
                process TEXT,
                command TEXT,
                severity TEXT NOT NULL DEFAULT 'info',
                raw_data TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
            CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
            CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_uid TEXT NOT NULL UNIQUE,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                reason TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                timestamp TEXT NOT NULL,
                source_logs TEXT NOT NULL DEFAULT '[]',
                indicators TEXT NOT NULL DEFAULT '{}',
                matched_pattern TEXT NOT NULL DEFAULT '',
                confidence REAL NOT NULL DEFAULT 1.0,
                metadata TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'new',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_uid TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                alert_uids TEXT NOT NULL DEFAULT '[]',
                indicators TEXT NOT NULL DEFAULT '{}',
                summary TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
            CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
            CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at);
            """
        )


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    """Return a configured SQLite connection using the current database path."""
    path = db_path or DEFAULT_DB_PATH
    init_db(path)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn
