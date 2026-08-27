from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from .alert_store import list_alerts
from .incident_store import create_incident


def _alert_time(alert: dict[str, Any]) -> datetime:
    value = datetime.fromisoformat(str(alert["timestamp"]).replace("Z", "+00:00"))
    return value


def correlation_keys(alert: dict[str, Any]) -> set[str]:
    indicators = alert.get("indicators") or {}
    keys: set[str] = set()
    for field in ("username", "source_ip", "destination_ip", "host"):
        value = indicators.get(field)
        if value:
            keys.add(f"{field}:{value}")
    return keys


def correlate_alerts(
    *,
    window_minutes: int = 15,
    min_alerts: int = 2,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    """Group nearby alerts sharing an identity/network/entity indicator."""
    alerts = list_alerts(status="new", limit=limit)
    alerts.sort(key=_alert_time)

    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        for key in correlation_keys(alert):
            buckets[key].append(alert)

    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    window = timedelta(minutes=window_minutes)

    for key, members in buckets.items():
        if len(members) < min_alerts:
            continue
        current: list[dict[str, Any]] = []
        for alert in members:
            current = [a for a in current if _alert_time(alert) - _alert_time(a) <= window]
            current.append(alert)
            if len(current) >= min_alerts:
                uids = tuple(sorted({str(a["alert_uid"]) for a in current}))
                if len(uids) >= min_alerts and uids not in seen:
                    seen.add(uids)
                    candidates.append({"correlation_key": key, "alert_uids": list(uids)})

    return candidates


def create_correlated_incidents(
    *,
    window_minutes: int = 15,
    min_alerts: int = 2,
) -> list[dict[str, Any]]:
    """Turn correlated alert groups into deterministic incidents."""
    candidates = correlate_alerts(window_minutes=window_minutes, min_alerts=min_alerts)
    created: list[dict[str, Any]] = []

    for candidate in candidates:
        key = candidate["correlation_key"]
        alert_uids = candidate["alert_uids"]
        summary = (
            f"SentinelX correlated {len(alert_uids)} alerts sharing {key} "
            f"within {window_minutes} minutes."
        )
        incident = create_incident(
            title=f"Correlated security activity: {key}",
            alert_uids=alert_uids,
            indicators={"correlation_key": key},
            summary=summary,
        )
        created.append(incident)
    return created
