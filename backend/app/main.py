from datetime import datetime, timezone
from typing import Any

try:
    from fastapi import FastAPI
except ImportError:  # Keeps this module importable before dependencies are installed.
    FastAPI = None


APP_VERSION = "0.1.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if FastAPI:
    app = FastAPI(
        title="SentinelX SOC API",
        description="Offline-first Security Operations and Detection Platform",
        version=APP_VERSION,
    )

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
            ],
        }
else:
    app = None
