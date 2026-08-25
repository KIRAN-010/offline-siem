"""CSV log parser."""

import csv
from datetime import datetime, timezone
from io import StringIO
from typing import Iterator

from src.parsers.base import BaseParser
from src.schema import LogLevel, NormalizedLog


class CSVParser(BaseParser):
    """Parser for CSV-formatted logs."""

    TIMESTAMP_COLUMNS = ["timestamp", "time", "datetime", "date", "ts", "@timestamp"]
    LEVEL_COLUMNS = ["level", "severity", "log_level", "loglevel", "priority"]
    MESSAGE_COLUMNS = ["message", "msg", "text", "log", "description", "content"]
    LOGGER_COLUMNS = ["logger", "logger_name", "name", "source", "component"]
    SOURCE_COLUMNS = ["source", "file", "filename", "path"]
    FUNCTION_COLUMNS = ["function", "func", "funcName", "method"]
    LINE_COLUMNS = ["line", "line_number", "lineno", "lineNumber"]

    @property
    def name(self) -> str:
        return "csv"

    @property
    def supported_extensions(self) -> list[str]:
        return [".csv"]

    def parse(self, content: str) -> Iterator[NormalizedLog]:
        reader = csv.DictReader(StringIO(content))
        for row in reader:
            if row and any(v for v in row.values() if v):
                yield self._parse_row(row, self._row_to_raw(row))

    @staticmethod
    def _row_to_raw(row: dict) -> str:
        return ",".join(str(v or "") for v in row.values())

    def _parse_row(self, row: dict, raw_line: str) -> NormalizedLog:
        columns = {str(k).lower(): v for k, v in row.items() if k is not None}
        known_columns = set(self.TIMESTAMP_COLUMNS + self.LEVEL_COLUMNS + self.MESSAGE_COLUMNS + self.LOGGER_COLUMNS + self.SOURCE_COLUMNS + self.FUNCTION_COLUMNS + self.LINE_COLUMNS)
        metadata = {k: v for k, v in columns.items() if k not in known_columns and v}
        return NormalizedLog(
            timestamp=self._extract_timestamp(columns),
            level=self._extract_level(columns),
            message=self._extract_message(columns),
            logger=self._extract_column(columns, self.LOGGER_COLUMNS),
            source=self._extract_column(columns, self.SOURCE_COLUMNS),
            function=self._extract_column(columns, self.FUNCTION_COLUMNS),
            line_number=self._extract_line_number(columns),
            metadata=metadata,
            raw_line=raw_line,
            format="csv",
        )

    def _extract_timestamp(self, columns: dict) -> datetime:
        for col in self.TIMESTAMP_COLUMNS:
            value = columns.get(col)
            if not value:
                continue
            try:
                ts = float(value)
                return datetime.fromtimestamp(ts / 1000 if ts > 1e11 else ts, tz=timezone.utc).replace(tzinfo=None)
            except (ValueError, TypeError):
                pass
            try:
                dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
            except ValueError:
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
                    try:
                        return datetime.strptime(str(value), fmt)
                    except ValueError:
                        pass
        return datetime.now()

    def _extract_level(self, columns: dict) -> LogLevel:
        for col in self.LEVEL_COLUMNS:
            value = columns.get(col)
            if value in (None, ""):
                continue
            if isinstance(value, str):
                normalized = {"WARN": "WARNING", "ERR": "ERROR", "FATAL": "CRITICAL"}.get(value.upper(), value.upper())
                try:
                    return LogLevel(normalized)
                except ValueError:
                    return LogLevel.UNKNOWN
            if isinstance(value, (int, float)):
                return {10: LogLevel.DEBUG, 20: LogLevel.INFO, 30: LogLevel.WARNING, 40: LogLevel.ERROR, 50: LogLevel.CRITICAL}.get(int(value), LogLevel.UNKNOWN)
        return LogLevel.UNKNOWN

    def _extract_message(self, columns: dict) -> str:
        for col in self.MESSAGE_COLUMNS:
            if columns.get(col):
                return str(columns[col])
        return " | ".join(str(v) for v in columns.values() if v)

    @staticmethod
    def _extract_column(columns: dict, candidates: list[str]) -> str:
        for col in candidates:
            if columns.get(col):
                return str(columns[col])
        return ""

    def _extract_line_number(self, columns: dict) -> int | None:
        for col in self.LINE_COLUMNS:
            if columns.get(col):
                try:
                    return int(columns[col])
                except (ValueError, TypeError):
                    return None
        return None
