"""Brute-force authentication detection."""

import logging
import re
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Iterator

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class BruteForceDetector(BaseDetector):
    """Detect repeated authentication failures with a sliding time window."""

    def __init__(
        self,
        threshold: int | None = None,
        window_seconds: int | None = None,
        severity_threshold: int | None = None,
        moving_avg_window: int | None = None,
        deviation_threshold: float | None = None,
        min_baseline_events: int | None = None,
        **_: object,
    ):
        from src.config import load_config

        cfg = load_config().get("detection", {}).get("brute_force", {})
        self.threshold = max(1, int(threshold if threshold is not None else cfg.get("threshold", 5)))
        self.window_seconds = max(1, int(window_seconds if window_seconds is not None else cfg.get("window_seconds", 300)))
        self.severity_threshold = max(self.threshold, int(severity_threshold if severity_threshold is not None else cfg.get("severity_threshold", 20)))
        self.moving_avg_window = max(3, int(moving_avg_window if moving_avg_window is not None else cfg.get("moving_avg_window", 10)))
        self.deviation_threshold = float(deviation_threshold if deviation_threshold is not None else cfg.get("deviation_threshold", 2.0))
        self.min_baseline_events = max(3, int(min_baseline_events if min_baseline_events is not None else cfg.get("min_baseline_events", 50)))
        self.baseline_data: dict[str, deque[int]] = defaultdict(lambda: deque(maxlen=self.moving_avg_window))

    @property
    def name(self) -> str:
        return "BruteForceDetector"

    @property
    def description(self) -> str:
        return "Sliding-window authentication failure detection with optional statistical context"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        failures: dict[str, list[NormalizedLog]] = defaultdict(list)
        for log in logs:
            if self._is_auth_failure(log):
                identifier = self._get_identifier(log)
                if identifier:
                    failures[identifier].append(log)

        for source, entries in failures.items():
            yield from self._analyze_failures(source, entries)

    def _analyze_failures(self, source: str, entries: list[NormalizedLog]) -> Iterator[Alert]:
        entries.sort(key=lambda x: x.timestamp)
        left = 0
        alerted_windows: set[tuple[str, str]] = set()

        for right, current in enumerate(entries):
            while current.timestamp - entries[left].timestamp > timedelta(seconds=self.window_seconds):
                left += 1
            window = entries[left:right + 1]
            count = len(window)
            if count < self.threshold:
                continue

            first = window[0].timestamp.isoformat()
            last = window[-1].timestamp.isoformat()
            window_key = (first, last)
            if window_key in alerted_windows:
                continue
            alerted_windows.add(window_key)

            anomaly = self._is_statistical_anomaly(source, count)
            severity = self._calculate_severity(count, anomaly)
            yield Alert(
                id=self._generate_alert_id("BRUTE", source, f"{first}:{last}"),
                alert_type=AlertType.BRUTE_FORCE,
                severity=severity,
                reason=f"Brute force attack detected from {source}",
                description=(f"Detected {count} authentication failures within {self.window_seconds} seconds"
                             + ("; frequency is statistically anomalous" if anomaly else ".")),
                source_logs=[log.raw_line for log in window[:10]],
                indicators={"source": source, "failure_count": count, "window_seconds": self.window_seconds},
                matched_pattern=f"{count} failures/{self.window_seconds}s",
                confidence=self._calculate_confidence(count, anomaly),
                metadata={
                    "threshold": self.threshold,
                    "severity_threshold": self.severity_threshold,
                    "statistical_anomaly": anomaly,
                    "first_failure": first,
                    "last_failure": last,
                },
            )

    def _is_statistical_anomaly(self, source: str, count: int) -> bool:
        baseline = self.baseline_data[source]
        anomaly = False
        minimum = min(self.moving_avg_window, max(3, self.min_baseline_events // 10))
        if len(baseline) >= minimum:
            mean = statistics.mean(baseline)
            stdev = statistics.stdev(baseline) if len(baseline) > 1 else 0
            anomaly = count > mean * 1.5 if stdev == 0 else ((count - mean) / stdev > self.deviation_threshold)
        baseline.append(count)
        return anomaly

    def _calculate_severity(self, count: int, anomaly: bool) -> AlertSeverity:
        if count >= self.severity_threshold:
            return AlertSeverity.CRITICAL
        if count >= self.threshold * 2 or anomaly:
            return AlertSeverity.HIGH
        if count >= self.threshold * 1.5:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def _calculate_confidence(self, count: int, anomaly: bool) -> float:
        base = min(0.9, count / max(1, self.threshold * 2))
        return min(0.95, base + 0.1) if anomaly else base

    @staticmethod
    def _is_auth_failure(log: NormalizedLog) -> bool:
        message = log.message.lower()
        indicators = (
            "failed", "failure", "authentication failed", "login failed",
            "invalid credentials", "bad credentials", "wrong password",
            "invalid username", "account locked", "access denied", "unauthorized",
            "登入失败", "认证失败",
        )
        return any(indicator in message for indicator in indicators)

    @staticmethod
    def _get_identifier(log: NormalizedLog) -> str | None:
        value = log.metadata.get("ip") or log.metadata.get("source_ip")
        if value:
            return str(value)
        match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log.raw_line)
        if match:
            return match.group(0)
        return log.logger or log.source or None
