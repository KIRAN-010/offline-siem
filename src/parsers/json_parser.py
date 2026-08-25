"""JSON log parser."""

import json
import re
from datetime import datetime, timezone
from typing import Iterator

from src.parsers.base import BaseParser
from src.schema import LogLevel, NormalizedLog


class JSONParser(BaseParser):
    """Parser for JSON and JSON Lines logs."""

    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    @property
    def name(self) -> str:
        return "json"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json", ".jsonl"]

    def parse(self, content: str) -> Iterator[NormalizedLog]:
        """Parse JSON object, JSON array, or JSON Lines content."""
        text = content.strip()
        if not text:
            return

        try:
            data = json.loads(text)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        yield self._parse_entry(entry, json.dumps(entry))
                return
            if isinstance(data, dict):
                yield self._parse_entry(data, text)
                return
        except json.JSONDecodeError:
            pass

        # JSON Lines fallback.
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                yield self._parse_entry(entry, line)

    def _parse_entry(self, entry: dict, raw_line: str) -> NormalizedLog:
        metadata = dict(entry)
        timestamp = self._extract_timestamp(entry)
        level = self._extract_level(entry)
        message = self._extract_message(entry)

        logger = str(entry.get("logger") or entry.get("name") or entry.get("logger_name") or "")
        source = str(entry.get("source") or entry.get("file") or entry.get("filename") or "")
        function = str(entry.get("function") or entry.get("funcName") or entry.get("method") or "")
        line_number = entry.get("line") or entry.get("lineNumber") or entry.get("lineno")

        known_fields = {
            "timestamp", "time", "datetime", "@timestamp", "ts",
            "level", "severity", "log_level", "loglevel",
            "message", "msg", "text", "log", "logger", "name", "logger_name",
            "source", "file", "filename", "function", "funcName", "method",
            "line", "lineNumber", "lineno", "ip", "source_ip", "client_ip", "remote_ip", "host",
        }
        metadata = {k: v for k, v in metadata.items() if k not in known_fields}

        ip = self._extract_ip(entry, message)
        if ip:
            metadata["ip"] = ip

        return NormalizedLog(
            timestamp=timestamp,
            level=level,
            message=message,
            logger=logger,
            source=source,
            function=function,
            line_number=line_number,
            metadata=metadata,
            raw_line=raw_line,
            format="json",
        )

    @staticmethod
    def _extract_timestamp(entry: dict) -> datetime:
        for field in ["timestamp", "time", "datetime", "@timestamp", "ts"]:
            value = entry.get(field)
            if value in (None, ""):
                continue
            if isinstance(value, (int, float)):
                return datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc).replace(tzinfo=None)
            if isinstance(value, str):
                try:
                    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
                except ValueError:
                    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"]:
                        try:
                            return datetime.strptime(value, fmt)
                        except ValueError:
                            pass
        return datetime.now()

    @staticmethod
    def _extract_level(entry: dict) -> LogLevel:
        value = next((entry.get(k) for k in ["level", "severity", "log_level", "loglevel"] if entry.get(k) is not None), None)
        if isinstance(value, str):
            normalized = {"WARN": "WARNING", "ERR": "ERROR", "FATAL": "CRITICAL"}.get(value.upper(), value.upper())
            try:
                return LogLevel(normalized)
            except ValueError:
                return LogLevel.UNKNOWN
        if isinstance(value, (int, float)):
            return {10: LogLevel.DEBUG, 20: LogLevel.INFO, 30: LogLevel.WARNING, 40: LogLevel.ERROR, 50: LogLevel.CRITICAL}.get(int(value), LogLevel.UNKNOWN)
        return LogLevel.UNKNOWN

    @staticmethod
    def _extract_message(entry: dict) -> str:
        for field in ["message", "msg", "text", "log"]:
            if entry.get(field) is not None:
                return str(entry[field])
        return str(entry)

    def _extract_ip(self, entry: dict, message: str) -> str | None:
        for field in ["ip", "source_ip", "client_ip", "remote_ip", "host"]:
            value = entry.get(field)
            if value:
                match = self.IP_PATTERN.search(str(value))
                if match:
                    return match.group(0)
        match = self.IP_PATTERN.search(message)
        return match.group(0) if match else None
