"""Report signing and hashing utilities."""

import hashlib
import hmac
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ReportSigner:
    """Sign and verify report integrity."""

    def __init__(self, secret_key: str | None = None):
        self.secret_key = secret_key or self._get_default_secret()

    def _get_default_secret(self) -> str:
        """Get or create default secret key."""
        data_dir = Path(__file__).parent.parent.parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        secret_file = data_dir / ".secret"

        if secret_file.exists():
            return secret_file.read_text().strip()

        # Generate new secret
        import secrets
        secret = secrets.token_hex(32)
        secret_file.write_text(secret)
        return secret

    def sign_content(self, content: str) -> str:
        """Create HMAC signature for content."""
        signature = hmac.new(
            self.secret_key.encode(),
            content.encode(),
            hashlib.sha256,
        ).hexdigest()
        return signature

    def verify_signature(self, content: str, signature: str) -> bool:
        """Verify content signature."""
        expected = self.sign_content(content)
        return hmac.compare_digest(expected, signature)

    def compute_content_hash(self, content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()

    def compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        hash_obj = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def create_report_signature(
        self,
        report_content: str,
        metadata: dict,
    ) -> dict:
        """Create a signed report with metadata."""
        content_hash = self.compute_content_hash(report_content)
        signature = self.sign_content(report_content)

        return {
            "content_hash": content_hash,
            "signature": signature,
            "signed_at": datetime.now().isoformat(),
            "metadata": metadata,
        }

    def verify_report(
        self,
        report_content: str,
        signature_data: dict,
    ) -> bool:
        """Verify a signed report."""
        # Verify content hash
        content_hash = self.compute_content_hash(report_content)
        if content_hash != signature_data.get("content_hash"):
            logger.warning("Content hash mismatch")
            return False

        # Verify signature
        signature = signature_data.get("signature", "")
        if not self.verify_signature(report_content, signature):
            logger.warning("Signature verification failed")
            return False

        return True


# Global signer instance
_signer: ReportSigner | None = None


def get_signer() -> ReportSigner:
    """Get global signer instance."""
    global _signer
    if _signer is None:
        _signer = ReportSigner()
    return _signer