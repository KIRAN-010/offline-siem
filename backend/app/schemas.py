from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator


class SecurityEvent(BaseModel):
    """Canonical event shape used by SentinelX detection components."""

    timestamp: datetime
    source: str = Field(min_length=1, max_length=100)
    host: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    event_id: str | None = Field(default=None, max_length=100)
    process: str | None = Field(default=None, max_length=500)
    command: str | None = Field(default=None, max_length=2000)
    severity: str = Field(default="info", max_length=20)
    raw_data: dict[str, Any] = Field(default_factory=dict)

    @field_validator('timestamp')
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        # Treat timezone-less local imports as UTC consistently.
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
