"""Plain text log parser."""

import logging
import re
from datetime import datetime
from typing import Iterator

from src.parsers.base import BaseParser
from src.schema import LogLevel, NormalizedLog


class PlainTextParser(BaseParser):
    """Parser for plain text logs.

    Supports common timestamp/level patterns and extracts IP addresses.
    """

    IP_PATTERN = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
    ISO_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\s+"
        r"(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\s+"
        r"(?:\[(?P<logger>[^\]]+)\]\s+)?"
        r"(?P<message>.*)$"
    )
    BRACKETED_PATTERN = re.compile(
        r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\]\s+"
        r"\[(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\]\s+"
        r"(?P<message>.*)$"
    )
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
        """Parse plain text log content line by line."""
        for raw_line in content.splitlines():
            entry = self.parse_line(raw_line)
            if entry:
                yield entry

    def parse_line(self, raw_line: str) -> NormalizedLog | None:
        """Parse one line, preserving the original line for investigation."""
        line = raw_line.strip()
        if not line:
            return None

        for pattern in (self.ISO_PATTERN, self.BRACKETED_PATTERN, self.SIMPLE_PATTERN):
            match = pattern.match(line)
            if match:
                return self._create_entry(match.groupdict(), line)

        return self._create_generic_entry(line)

    def _create_generic_entry(self, raw_line: str) -> NormalizedLog:
        ip_match = self.IP_PATTERN.search(raw_line)
        ip = ip_match.group(0) if ip_match else ""
        return NormalizedLog(
            timestamp=datetime.now(),
            level=self._infer_level(raw_line),
            message=raw_line,
            raw_line=raw_line,
            format="text",
            metadata={"ip": ip} if ip else {},
        )

    def _create_entry(self, groups: dict, raw_line: str) -> NormalizedLog:
        timestamp = self._parse_timestamp(groups.get("timestamp", ""))
        level = self._parse_level(groups.get("level", "UNKNOWN"))
        message = groups.get("message", raw_line)
        logger = groups.get("logger", "")
        ip_match = self.IP_PATTERN.search(raw_line)
        ip = ip_match.group(0) if ip_match else ""
        return NormalizedLog(
            timestamp=timestamp,
            level=level,
            message=message,
            logger=logger,
            raw_line=raw_line,
            format="text",
            metadata={"ip": ip} if ip else {},
        )

    def _parse_timestamp(self, ts: str) -> datetime:
        ts = ts.replace(",", ".")
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        return datetime.now()

    def _infer_level(self, raw_line: str) -> LogLevel:
        line_lower = raw_line.lower()
        if any(word in line_lower for word in ("error", "fail", "failed", "failure", "exception", "critical")):
            return LogLevel.ERROR
        if any(word in line_lower for word in ("warn", "warning")):
            return LogLevel.WARNING
        if any(word in line_lower for word in ("info", "information")):
            return LogLevel.INFO
        if "debug" in line_lower:
            return LogLevel.DEBUG
        return LogLevel.UNKNOWN

    def _parse_level(self, level_str: str) -> LogLevel:
        level_str = level_str.upper()
        if "CRITICAL" in level_str or "FATAL" in level_str:
            return LogLevel.CRITICAL
        if "WARNING" in level_str or "WARN" in level_str:
            return LogLevel.WARNING
        if level_str == "TRACE":
            return LogLevel.DEBUG
        try:
            return LogLevel(level_str)
        except ValueError:
            return LogLevel.UNKNOWN
