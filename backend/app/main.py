from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .db import init_db
from .routes_alerts import router as alerts_router
from .routes_correlation import router as correlation_router
from .routes_dashboard import router as dashboard_router
from .routes_events import router as events_router
from .routes_hunting import router as hunting_router
from .routes_incidents import router as incidents_router
from .routes_investigation import router as investigation_router
from .routes_rules import router as rules_router


APP_VERSION = "0.9.0"

app = FastAPI(
    title="SentinelX SOC API",
    description="Offline-first Security Operations and Detection Platform",
    version=APP_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(dashboard_router)
app.include_router(incidents_router)
app.include_router(correlation_router)
app.include_router(investigation_router)
app.include_router(hunting_router)
app.include_router(rules_router)


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
            "rules",
            "alerts",
            "correlation",
            "risk",
            "incidents",
            "mitre-attack",
            "investigation",
            "threat-intel",
            "hunting",
            "reports",
            "dashboard",
        ],
    }
