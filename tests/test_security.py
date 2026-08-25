from src.security.password_gate import PasswordGate


def test_password_gate_requires_strong_password(tmp_path):
    gate = PasswordGate(tmp_path / ".password")
    assert gate.set_password("short") is False
    assert gate.is_password_set() is False


def test_password_gate_uses_salted_pbkdf2(tmp_path):
    path = tmp_path / ".password"
    gate = PasswordGate(path)
    assert gate.set_password("correct horse battery") is True
    record = path.read_text()
    assert record.startswith("pbkdf2_sha256$")
    assert gate.verify("correct horse battery") is True
    assert gate.verify("wrong password") is False


def test_password_gate_hashes_same_password_differently(tmp_path):
    p1 = tmp_path / "one"
    p2 = tmp_path / "two"
    g1 = PasswordGate(p1)
    g2 = PasswordGate(p2)
    assert g1.set_password("correct horse battery")
    assert g2.set_password("correct horse battery")
    assert p1.read_text() != p2.read_text()
