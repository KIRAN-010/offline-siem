"""Plain text log parser."""

import logging
import re
from datetime import datetime
from typing import Iterator

from src.parsers.base import BaseParser
from src.schema import LogLevel, NormalizedLog


class PlainTextParser(BaseParser):
    """Parser for plain text logs.

    Supports common patterns and extracts IP addresses.
    """

    # IP address pattern
    IP_PATTERN = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")

    # Pattern: YYYY-MM-DD HH:MM:SS,ms LEVEL [logger] message
    ISO_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\s+"
        r"(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\s+"
        r"(?:\[(?P<logger>[^\]]+)\]\s+)?"
        r"(?P<message>.*)$"
    )

    # Pattern: [timestamp] [level] message
    BRACKETED_PATTERN = re.compile(
        r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\]\s+"
        r"\[(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\]\s+"
        r"(?P<message>.*)$"
    )

    # Pattern: Simple date time level message
    SIMPLE_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\s+"
        r"(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\s+"
        r"(?P<message>.*)$"
    )

    @property
    def name(self) -> str:
        return "text"

    @property
    def supported_extensions(self) -> list[str]:
        return [".txt", ".log"]

    def parse(self, content: str) -> Iterator[NormalizedLog]:
        """Parse plain text log content."""
        lines = content.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            entry = self._parse_line(line)
            if entry:
                yield entry

    def _parse_line(self, raw_line: str) -> NormalizedLog | None:
        """Parse a single text log line."""
        # Try ISO pattern
        match = self.ISO_PATTERN.match(raw_line)
        if match:
            return self._create_entry(match.groupdict(), raw_line)

        # Try bracketed pattern
        match = self.BRACKETED_PATTERN.match(raw_line)
        if match:
            return self._create_entry(match.groupdict(), raw_line)

        # Try simple pattern
        match = self.SIMPLE_PATTERN.match(raw_line)
        if match:
            return self._create_entry(match.groupdict(), raw_line)

        # No structured match - create generic entry
        return self._create_generic_entry(raw_line)

    def _create_generic_entry(self, raw_line: str) -> NormalizedLog:
        """Create a generic entry for unstructured logs."""
        # Extract IP address
        ip_match = self.IP_PATTERN.search(raw_line)
        ip = ip_match.group(0) if ip_match else ""

        # Determine level based on content
        level = self._infer_level(raw_line)

        # Use entire line as message
        message = raw_line

        return NormalizedLog(
            timestamp=datetime.now(),
            level=level,
            message=message,
            raw_line=raw_line,
            format="text",
            metadata={"ip": ip} if ip else {},
        )

    def _create_entry(self, groups: dict, raw_line: str) -> NormalizedLog:
        """Create normalized entry from parsed groups."""
        # Parse timestamp
        timestamp = self._parse_timestamp(groups.get("timestamp", ""))

        # Parse level
        level_str = groups.get("level", "UNKNOWN")
        level = self._parse_level(level_str)

        # Extract message
        message = groups.get("message", raw_line)

        # Extract logger
        logger = groups.get("logger", "")

        # Extract IP from message
        ip_match = self.IP_PATTERN.search(raw_line)
        ip = ip_match.group(0) if ip_match else ""

        metadata = {"ip": ip} if ip else {}

        return NormalizedLog(
            timestamp=timestamp,
            level=level,
            message=message,
            logger=logger,
            raw_line=raw_line,
            format="text",
            metadata=metadata,
        )

        return NormalizedLog(
            timestamp=timestamp,
            level=level,
            message=message,
            logger=logger,
            raw_line=raw_line,
            format="text",
        )

    def _parse_timestamp(self, ts: str) -> datetime:
        """Parse timestamp string."""
        ts = ts.replace(",", ".")
        for fmt in ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        return datetime.now()

    def _infer_level(self, raw_line: str) -> LogLevel:
        """Infer log level from content."""
        line_lower = raw_line.lower()
        if any(word in line_lower for word in ["error", "fail", "failed", "failure", "exception", "critical"]):
            return LogLevel.ERROR
        elif any(word in line_lower for word in ["warn", "warning"]):
            return LogLevel.WARNING
        elif any(word in line_lower for word in ["info", "information"]):
            return LogLevel.INFO
        elif any(word in line_lower for word in ["debug"]):
            return LogLevel.DEBUG
        else:
            return LogLevel.UNKNOWN

    def _parse_level(self, level_str: str) -> LogLevel:
        """Parse log level string."""
        level_str = level_str.upper()
        # Handle WARNING -> WARN
        if "WARNING" in level_str:
            return LogLevel.WARNING
        if "WARN" in level_str:
            return LogLevel.WARNING
        if "CRITICAL" in level_str or "FATAL" in level_str:
            return LogLevel.CRITICAL

        try:
            return LogLevel(level_str)
        except ValueError:
            return LogLevel.UNKNOWN