from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI

from .db import init_db
from .routes_alerts import router as alerts_router
from .routes_dashboard import router as dashboard_router
from .routes_events import router as events_router


APP_VERSION = "0.4.0"

app = FastAPI(
    title="SentinelX SOC API",
    description="Offline-first Security Operations and Detection Platform",
    version=APP_VERSION,
)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(dashboard_router)


@app.on_event("startup")
def startup() -> None:
    """Ensure the local database schema exists before serving requests."""
    init_db()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "service": "sentinelx-api", "version": APP_VERSION}


@app.get("/ready")
def readiness() -> dict[str, Any]:
    return {"status": "ready", "timestamp": utc_now()}


@app.get("/api/v1")
def api_info() -> dict[str, Any]:
    return {
        "name": "SentinelX",
        "version": APP_VERSION,
        "modules": [
            "events",
            "detections",
            "alerts",
            "incidents",
            "threat-intel",
            "hunting",
            "reports",
            "dashboard",
        ],
    }
