"""Brute force detection."""

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Iterator

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import LogLevel, NormalizedLog

logger = logging.getLogger(__name__)


class BruteForceDetector(BaseDetector):
    """Detect brute force attack patterns.

    Identifies rapid repeated authentication failures from the same source.
    """

    def __init__(
        self,
        threshold: int = 10,
        window_minutes: int = 5,
        severity_threshold: int = 20,
    ):
        """Initialize detector.

        Args:
            threshold: Number of failures to trigger alert.
            window_minutes: Time window to analyze.
            severity_threshold: Number of failures for CRITICAL severity.
        """
        self.threshold = threshold
        self.window_minutes = window_minutes
        self.severity_threshold = severity_threshold

    @property
    def name(self) -> str:
        return "BruteForceDetector"

    @property
    def description(self) -> str:
        return "Detects brute force authentication attacks"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Detect brute force patterns."""
        # Track failures by source IP / identifier
        failures: dict[str, list[NormalizedLog]] = defaultdict(list)

        for log in logs:
            # Look for authentication failure indicators
            if self._is_auth_failure(log):
                key = self._get_identifier(log)
                if key:
                    failures[key].append(log)

        # Analyze each source
        for source, log_entries in failures.items():
            alerts = self._analyze_failures(source, log_entries)
            yield from alerts

    def _is_auth_failure(self, log: NormalizedLog) -> bool:
        """Check if log indicates an authentication failure."""
        # Check level
        if log.level not in (LogLevel.ERROR, LogLevel.WARNING):
            # Also check message content
            msg_lower = log.message.lower()
            failure_indicators = [
                "invalid credentials",
                "authentication failed",
                "login failed",
                "bad credentials",
                "wrong password",
                "invalid username",
                "account locked",
                "access denied",
                "unauthorized",
                "failed login",
                "登入失败",  # Chinese
                "认证失败",
            ]
            return any(ind in msg_lower for ind in failure_indicators)
        return True

    def _get_identifier(self, log: NormalizedLog) -> str | None:
        """Get source identifier (IP, user, etc.) from log."""
        # Try metadata first
        if ip := log.metadata.get("ip") or log.metadata.get("source_ip"):
            return ip

        # Try from logger name
        if log.logger:
            return log.logger

        # Try from source
        if log.source:
            return log.source

        return None

    def _analyze_failures(self, source: str, log_entries: list[NormalizedLog]) -> Iterator[Alert]:
        """Analyze failures from a single source."""
        if not log_entries:
            return

        # Sort by timestamp
        log_entries.sort(key=lambda x: x.timestamp)

        # Check for rapid failures within time window
        window_start = log_entries[0].timestamp
        window_end = window_start + timedelta(minutes=self.window_minutes)

        recent_failures = [l for l in log_entries if window_start <= l.timestamp <= window_end]

        if len(recent_failures) >= self.threshold:
            # Determine severity
            if len(recent_failures) >= self.severity_threshold:
                severity = AlertSeverity.CRITICAL
            elif len(recent_failures) >= self.threshold * 1.5:
                severity = AlertSeverity.HIGH
            else:
                severity = AlertSeverity.MEDIUM

            # Create alert
            yield Alert(
                id=self._generate_alert_id("BRUTE", source, str(len(recent_failures))),
                alert_type=AlertType.BRUTE_FORCE,
                severity=severity,
                reason=f"Brute force attack detected from {source}",
                description=f"Detected {len(recent_failures)} authentication failures within {self.window_minutes} minutes",
                source_logs=[log.raw_line for log in recent_failures[:5]],  # First 5 as samples
                indicators={"source": source, "failure_count": len(recent_failures)},
                matched_pattern=f"{len(recent_failures)} failures in {self.window_minutes}min window",
                confidence=0.9,
                metadata={
                    "threshold": self.threshold,
                    "window_minutes": self.window_minutes,
                    "first_failure": recent_failures[0].timestamp.isoformat(),
                    "last_failure": recent_failures[-1].timestamp.isoformat(),
                },
            )