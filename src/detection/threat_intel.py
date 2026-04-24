"""Suspicious IP detection using local threat intelligence."""

import logging
import re
from pathlib import Path
from typing import Iterator, Set

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class ThreatIntelDetector(BaseDetector):
    """Detect connections from known suspicious IPs.

    Uses a local threat intelligence list (IP blocklist).
    """

    # Default suspicious IP ranges (example private IPs often used in attacks)
    DEFAULT_SUSPICIOUS_IPS: Set[str] = {
        # Example - replace with actual threat intel
        # These are commonly used for testing/malicious activity
    }

    def __init__(
        self,
        threat_list: Set[str] | None = None,
        threat_file: Path | None = None,
    ):
        """Initialize detector.

        Args:
            threat_list: Set of suspicious IP addresses/patterns.
            threat_file: Path to file containing IPs (one per line).
        """
        self.suspicious_ips = threat_list or self.DEFAULT_SUSPICIOUS_IPS

        # Load from file if provided
        if threat_file and threat_file.exists():
            self._load_from_file(threat_file)

    def _load_from_file(self, file_path: Path) -> None:
        """Load suspicious IPs from a file."""
        try:
            content = file_path.read_text(encoding="utf-8")
            for line in content.split("\n"):
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith("#"):
                    self.suspicious_ips.add(line)
            logger.info(f"Loaded {len(self.suspicious_ips)} IPs from {file_path}")
        except Exception as e:
            logger.error(f"Error loading threat file: {e}")

    def add_threat(self, ip: str) -> None:
        """Add an IP to the threat list."""
        self.suspicious_ips.add(ip)

    def remove_threat(self, ip: str) -> None:
        """Remove an IP from the threat list."""
        self.suspicious_ips.discard(ip)

    @property
    def name(self) -> str:
        return "ThreatIntelDetector"

    @property
    def description(self) -> str:
        return "Detects connections from known malicious IPs"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Detect suspicious IPs in logs."""
        for log in logs:
            yield from self._check_log(log)

    def _check_log(self, log: NormalizedLog) -> Iterator[Alert]:
        """Check a single log for suspicious IPs."""
        # Extract IP from various fields
        ips = self._extract_ips(log)

        for ip in ips:
            if self._is_suspicious(ip):
                yield self._create_alert(log, ip)

    def _extract_ips(self, log: NormalizedLog) -> list[str]:
        """Extract IP addresses from log entry."""
        ips = []

        # Check metadata
        if ip := log.metadata.get("ip") or log.metadata.get("source_ip") or log.metadata.get("client_ip"):
            ips.append(ip)

        # Check source
        if log.source:
            ips.append(log.source)

        # Try to extract from message
        import re

        # IPv4 pattern
        ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        matches = re.findall(ipv4_pattern, log.message)
        ips.extend(matches)

        return ips

    def _is_suspicious(self, ip: str) -> bool:
        """Check if IP is in threat list."""
        # Exact match
        if ip in self.suspicious_ips:
            return True

        # Check CIDR patterns (simple implementation)
        for threat in self.suspicious_ips:
            if "/" in threat:
                if self._ip_in_cidr(ip, threat):
                    return True

        return False

    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP is in CIDR range."""
        import ipaddress

        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except (ValueError, TypeError):
            return False

    def _create_alert(self, log: NormalizedLog, ip: str) -> Alert:
        """Create alert for suspicious IP."""
        return Alert(
            id=self._generate_alert_id("IP", ip),
            alert_type=AlertType.SUSPICIOUS_IP,
            severity=AlertSeverity.HIGH,
            reason=f"Connection from known malicious IP: {ip}",
            description=f"Log contains connection from IP {ip} which is in the threat intelligence list",
            source_logs=[log.raw_line],
            indicators={"ip": ip},
            matched_pattern=ip,
            confidence=0.95,
            metadata={
                "threat_list_size": len(self.suspicious_ips),
            },
        )