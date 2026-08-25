"""Password gating using salted PBKDF2-HMAC-SHA256."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from pathlib import Path


class PasswordGate:
    """Password protection for sensitive operations."""

    ALGORITHM = "pbkdf2_sha256"
    ITERATIONS = 600_000
    SALT_BYTES = 16
    MIN_PASSWORD_LENGTH = 12

    def __init__(self, password_file: Path | None = None):
        self.password_file = password_file or self._get_default_password_file()
        self._record = self._load_password()

    def _get_default_password_file(self) -> Path:
        data_dir = Path(__file__).parent.parent.parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir / ".password"

    def _load_password(self) -> str | None:
        if self.password_file.exists():
            return self.password_file.read_text(encoding="utf-8").strip() or None
        return None

    def is_password_set(self) -> bool:
        return bool(self._record)

    def set_password(self, password: str) -> bool:
        if len(password or "") < self.MIN_PASSWORD_LENGTH:
            return False
        salt = secrets.token_bytes(self.SALT_BYTES)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, self.ITERATIONS)
        self._record = f"{self.ALGORITHM}${self.ITERATIONS}${salt.hex()}${derived.hex()}"
        self.password_file.write_text(self._record, encoding="utf-8")
        try:
            self.password_file.chmod(0o600)
        except OSError:
            pass
        return True

    def verify(self, password: str) -> bool:
        if not self.is_password_set():
            return True
        if not password:
            return False
        record = self._record or ""
        try:
            algorithm, iterations_text, salt_hex, expected_hex = record.split("$", 3)
            if algorithm != self.ALGORITHM:
                return self._verify_legacy_sha256(password, record)
            iterations = int(iterations_text)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(expected_hex)
            actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _verify_legacy_sha256(password: str, record: str) -> bool:
        legacy = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(legacy, record)

    def check(self, password: str) -> bool:
        return self.verify(password)

    def clear_password(self) -> bool:
        if self.password_file.exists():
            self.password_file.unlink()
        self._record = None
        return True


_password_gate: PasswordGate | None = None


def get_password_gate() -> PasswordGate:
    global _password_gate
    if _password_gate is None:
        _password_gate = PasswordGate()
    return _password_gate
