"""Anomaly detection using IsolationForest."""

import logging
from typing import Iterator

import numpy as np

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class AnomalyDetector(BaseDetector):
    """Detect anomalies in log patterns using IsolationForest.

    Identifies unusual log patterns that don't match normal behavior.
    """

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        threshold: float = 0.5,
    ):
        """Initialize detector.

        Args:
            contamination: Expected proportion of anomalies.
            n_estimators: Number of isolation trees.
            threshold: Anomaly score threshold (0-1).
        """
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.threshold = threshold
        self._model = None
        self._feature_names = [
            "hour",
            "day_of_week",
            "level_encoded",
            "message_length",
            "has_ip",
            "has_username",
        ]

    @property
    def name(self) -> str:
        return "AnomalyDetector"

    @property
    def description(self) -> str:
        return "Detects anomalous log patterns using machine learning"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Detect anomalies in log stream."""
        # Collect logs for batch processing
        log_list = list(logs)

        if len(log_list) < 10:
            logger.warning("Not enough logs for anomaly detection")
            return

        # Extract features
        features = self._extract_features(log_list)

        if features.shape[0] == 0:
            return

        # Train and predict
        try:
            from sklearn.ensemble import IsolationForest

            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=42,
            )

            # Fit on all data
            self._model.fit(features)

            # Predict (-1 for anomaly, 1 for normal)
            predictions = self._model.predict(features)

            # Get anomaly scores
            scores = self._model.score_samples(features)

            # Yield alerts for anomalies
            for i, (log, pred, score) in enumerate(zip(log_list, predictions, scores)):
                if pred == -1 and score < (1 - self.threshold):
                    yield self._create_alert(log, score)
        except ImportError:
            logger.error("sklearn not installed. Install with: pip install scikit-learn")
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")

    def _extract_features(self, logs: list[NormalizedLog]) -> np.ndarray:
        """Extract numerical features from logs."""
        features = []

        for log in logs:
            # Time-based features
            hour = log.timestamp.hour
            day_of_week = log.timestamp.weekday()

            # Level encoding
            level_map = {
                "DEBUG": 0,
                "INFO": 1,
                "WARNING": 2,
                "ERROR": 3,
                "CRITICAL": 4,
                "UNKNOWN": 0,
            }
            level_encoded = level_map.get(log.level.value, 0)

            # Message length
            message_length = len(log.message)

            # Has IP indicator
            has_ip = 1 if any(
                k in log.metadata
                for k in ["ip", "source_ip", "client_ip", "remote_addr"]
            ) else 0

            # Has username indicator
            has_username = 1 if any(
                k in log.metadata
                for k in ["username", "user", "account"]
            ) else 0

            features.append(
                [hour, day_of_week, level_encoded, message_length, has_ip, has_username]
            )

        return np.array(features)

    def _create_alert(self, log: NormalizedLog, score: float) -> Alert:
        """Create alert for anomalous log."""
        # Convert score (more negative = more anomalous)
        anomaly_score = abs(score)

        # Determine severity based on score
        if anomaly_score > 0.8:
            severity = AlertSeverity.HIGH
        elif anomaly_score > 0.6:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW

        return Alert(
            id=self._generate_alert_id("ANO", str(int(score * 100))),
            alert_type=AlertType.ANOMALY,
            severity=severity,
            reason="Anomalous log pattern detected",
            description=f"Log entry deviates from normal patterns (anomaly score: {anomaly_score:.2f})",
            source_logs=[log.raw_line],
            indicators={
                "anomaly_score": float(anomaly_score),
                "timestamp": log.timestamp.isoformat(),
            },
            matched_pattern=f"score={score:.3f}",
            confidence=float(anomaly_score),
            metadata={
                "log_level": log.level.value,
                "logger": log.logger,
                "message_length": len(log.message),
            },
        )