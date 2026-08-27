from src.detection.engine import DetectionEngine
from src.schema import LogLevel, NormalizedLog

from .schemas import SecurityEvent


_LEVEL_MAP = {
    "debug": LogLevel.DEBUG,
    "info": LogLevel.INFO,
    "warning": LogLevel.WARNING,
    "warn": LogLevel.WARNING,
    "error": LogLevel.ERROR,
    "critical": LogLevel.CRITICAL,
}


def to_normalized(event: SecurityEvent) -> NormalizedLog:
    """Adapt the API event schema to the repository's detection schema."""
    metadata = dict(event.raw_data)
    if event.host:
        metadata.setdefault("host", event.host)
    if event.username:
        metadata.setdefault("username", event.username)
    if event.source_ip:
        metadata.setdefault("source_ip", event.source_ip)
    if event.destination_ip:
        metadata.setdefault("destination_ip", event.destination_ip)
    if event.process:
        metadata.setdefault("process", event.process)
    if event.event_id:
        metadata.setdefault("event_id", event.event_id)

    level = _LEVEL_MAP.get(event.severity.lower(), LogLevel.UNKNOWN)
    message = event.command or event.raw_data.get("message") or event.raw_data.get("msg") or event.source
    return NormalizedLog(
        timestamp=event.timestamp,
        level=level,
        message=str(message),
        logger=event.source,
        source=event.source,
        metadata=metadata,
        raw_line=str(event.raw_data.get("raw_line", message)),
        format="api",
    )


def detect_events(events: list[SecurityEvent]) -> list:
    """Run the existing detector suite against canonical API events."""
    if not events:
        return []
    normalized = [to_normalized(event) for event in events]
    return DetectionEngine().detect_batch(normalized)
