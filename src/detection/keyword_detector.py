"""Suspicious keyword detection."""

import hashlib
import logging
import re
from typing import Iterator

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class KeywordDetector(BaseDetector):
    """Detect security-relevant patterns in log messages."""

    DEFAULT_KEYWORDS = {
        AlertSeverity.CRITICAL: [r"sql\s+injection", r"xss\s+attack", r"command\s+injection", r"remote\s+code\s+execution", r"rce\b", r"buffer\s+overflow", r"zero.?day", r"exploit\s+kit"],
        AlertSeverity.HIGH: [r"unauthorized\s+access", r"privilege\s+escalation", r"data\s+exfiltration", r"data\s+breach", r"credential\s+theft", r"password\s+dump", r"reverse\s+shell", r"bind\s+shell"],
        AlertSeverity.MEDIUM: [r"injection", r"script\s+injection", r"path\s+traversal", r"directory\s+traversal", r"csrf", r"cross[\-\s]site", r"session\s+hijack", r"man[\-\s]in[\-\s]the[\-\s]middle"],
        AlertSeverity.LOW: [r"suspicious", r"anomal", r"unusual\s+activity", r"failed\s+attempt", r"blocked", r"denied", r"forbidden"],
    }

    def __init__(self, keywords: dict[AlertSeverity, list[str]] | None = None, case_sensitive: bool = False, **_: object):
        self.keywords = keywords or self.DEFAULT_KEYWORDS
        self.case_sensitive = case_sensitive
        flags = 0 if case_sensitive else re.IGNORECASE
        self._compiled_patterns = {severity: [re.compile(pattern, flags) for pattern in patterns] for severity, patterns in self.keywords.items()}

    @property
    def name(self) -> str:
        return "KeywordDetector"

    @property
    def description(self) -> str:
        return "Detects suspicious keywords and patterns"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        for log in logs:
            yield from self._check_log(log)

    def _check_log(self, log: NormalizedLog) -> Iterator[Alert]:
        seen: set[tuple[str, AlertSeverity]] = set()
        for severity, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(log.message)
                if not match:
                    continue
                key = (match.group(0).lower(), severity)
                if key in seen:
                    continue
                seen.add(key)
                yield self._create_alert(log, severity, pattern.pattern, match.group(0))

    def _create_alert(self, log: NormalizedLog, severity: AlertSeverity, pattern: str, matched: str) -> Alert:
        stable_id = hashlib.sha256(f"{log.timestamp.isoformat()}|{log.raw_line}|{severity.value}|{pattern}".encode()).hexdigest()[:16]
        return Alert(
            id=self._generate_alert_id("KW", stable_id),
            alert_type=AlertType.SUSPICIOUS_KEYWORD,
            severity=severity,
            reason=f"Suspicious keyword detected: {matched}",
            description=f"Log message contains suspicious pattern: '{matched}'",
            source_logs=[log.raw_line],
            indicators={"keyword": matched, "pattern": pattern},
            matched_pattern=matched,
            confidence=0.95,
            metadata={"log_level": log.level.value, "logger": log.logger},
        )
