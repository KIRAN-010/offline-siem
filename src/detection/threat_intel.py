"""Offline threat intelligence management and detection."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, Optional, Set

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class ThreatIntelManager:
    """Manage versioned offline IP intelligence with content integrity checks."""

    def __init__(self, intel_dir: Path | None = None):
        self.intel_dir = intel_dir or Path("data/threat_intel")
        self.intel_dir.mkdir(parents=True, exist_ok=True)
        self.suspicious_ips: Set[str] = set()
        self.current_version: Optional[str] = None
        self.last_updated: Optional[datetime] = None
        self.version_history: Dict[str, Dict] = {}

    def load_current_intel(self) -> bool:
        try:
            files = list(self.intel_dir.glob("threat_intel_v*.json"))
            if files:
                latest = max(files, key=lambda p: p.stat().st_mtime)
                return self.load_intel_file(latest)

            # Use the repository's sample intelligence as a safe local seed.
            sample = Path("samples/threat_intel.json")
            if sample.exists():
                return self.load_intel_file(sample)
            logger.warning("No offline threat intelligence found")
            return False
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.error("Error loading threat intelligence: %s", exc)
            return False

    def load_intel_file(self, file_path: Path) -> bool:
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            ips = self._extract_ips(data)
            if not ips:
                logger.error("No valid threat IPs found in %s", file_path)
                return False

            expected_hash = data.get("content_sha256")
            if expected_hash and not hmac.compare_digest(expected_hash, self._content_hash(ips)):
                logger.error("Threat intelligence integrity check failed: %s", file_path)
                return False

            version = str(data.get("version") or data.get("threat_intel", {}).get("version") or file_path.stem)
            created = data.get("created_at") or data.get("updated")
            try:
                updated = datetime.fromisoformat(str(created).replace("Z", "+00:00")) if created else datetime.now()
                updated = updated.replace(tzinfo=None)
            except ValueError:
                updated = datetime.now()

            self.suspicious_ips = ips
            self.current_version = version
            self.last_updated = updated
            self.version_history[version] = {"file_path": file_path, "loaded_at": datetime.now(), "ip_count": len(ips)}
            return True
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            logger.error("Error loading threat intelligence file %s: %s", file_path, exc)
            return False

    def import_external_intel(self, source_file: Path, version: str | None = None) -> bool:
        try:
            source = json.loads(source_file.read_text(encoding="utf-8"))
            ips = self._extract_ips(source)
            if not ips:
                return False
            version = version or datetime.now().strftime("%Y%m%d_%H%M%S")
            intel_file = self.intel_dir / f"threat_intel_v{version}.json"
            payload = {
                "version": version,
                "created_at": datetime.now().isoformat(),
                "threat_ips": sorted(ips),
                "content_sha256": self._content_hash(ips),
                "description": source.get("description", f"Imported from {source_file.name}"),
            }
            intel_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            return self.load_intel_file(intel_file)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            logger.error("Error importing threat intelligence: %s", exc)
            return False

    def rollback_to_version(self, version: str) -> bool:
        info = self.version_history.get(version)
        return bool(info and self.load_intel_file(info["file_path"]))

    def get_version_history(self) -> Dict[str, Dict]:
        return self.version_history.copy()

    @staticmethod
    def _extract_ips(data: dict) -> set[str]:
        raw = data.get("threat_ips", [])
        if not raw and isinstance(data.get("suspicious_ips"), list):
            raw = data["suspicious_ips"]
        result: set[str] = set()
        for item in raw:
            value = item.get("ip") if isinstance(item, dict) else item
            if not isinstance(value, str):
                continue
            try:
                if "/" in value:
                    ipaddress.ip_network(value, strict=False)
                else:
                    ipaddress.ip_address(value)
                result.add(value)
            except ValueError:
                logger.warning("Ignoring invalid threat IP/CIDR: %s", value)
        return result

    @staticmethod
    def _content_hash(ips: set[str]) -> str:
        canonical = "\n".join(sorted(ips)).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


class ThreatIntelDetector(BaseDetector):
    """Detect IPs present in the offline threat intelligence set."""

    def __init__(self, intel_manager: ThreatIntelManager | None = None, **_: object):
        self.intel_manager = intel_manager or ThreatIntelManager()
        if not self.intel_manager.load_current_intel():
            logger.warning("No threat intel loaded; detector will use an empty set")

    @property
    def name(self) -> str:
        return "ThreatIntelDetector"

    @property
    def description(self) -> str:
        return "Detects connections from known suspicious IPs using offline intelligence"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        for log in logs:
            for ip in self._extract_ips(log):
                if self._is_suspicious(ip):
                    yield self._create_alert(log, ip)

    def _extract_ips(self, log: NormalizedLog) -> list[str]:
        values = [log.metadata.get(k) for k in ("ip", "source_ip", "client_ip")]
        if log.source:
            values.append(log.source)
        values.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log.message))
        return list(dict.fromkeys(str(v) for v in values if v))

    def _is_suspicious(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for threat in self.intel_manager.suspicious_ips:
            try:
                if "/" in threat and address in ipaddress.ip_network(threat, strict=False):
                    return True
                if address == ipaddress.ip_address(threat):
                    return True
            except ValueError:
                continue
        return False

    def _create_alert(self, log: NormalizedLog, ip: str) -> Alert:
        version = self.intel_manager.current_version or "unknown"
        return Alert(
            id=self._generate_alert_id("IP", ip),
            alert_type=AlertType.SUSPICIOUS_IP,
            severity=AlertSeverity.HIGH,
            reason=f"Connection from known suspicious IP: {ip}",
            description=f"Log contains {ip}, present in offline threat intelligence {version}",
            source_logs=[log.raw_line],
            indicators={"ip": ip, "threat_intel_version": self.intel_manager.current_version},
            matched_pattern=ip,
            confidence=0.95,
            metadata={"threat_list_size": len(self.intel_manager.suspicious_ips)},
        )

    def import_threat_intel(self, file_path: Path, version: str | None = None) -> bool:
        return self.intel_manager.import_external_intel(file_path, version)

    def get_intel_stats(self) -> Dict:
        return {
            "current_version": self.intel_manager.current_version,
            "threat_ip_count": len(self.intel_manager.suspicious_ips),
            "last_updated": self.intel_manager.last_updated.isoformat() if self.intel_manager.last_updated else None,
            "version_history": list(self.intel_manager.version_history.keys()),
        }
