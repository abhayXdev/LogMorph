"""Unit tests for password hashing and verification utilities."""

from logmorph.core.security import hash_password, verify_password


def test_hash_password_generates_valid_bcrypt_format():
    """Verify that hash_password returns a bcrypt formatted string."""
    password = "SuperSecretPassword123!"
    hashed = hash_password(password)

    assert isinstance(hashed, str)
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
    assert len(hashed) >= 59


def test_verify_password_success():
    """Verify that correct password matches the hash."""
    password = "ValidUserPassword#2026"
    hashed = hash_password(password)

    assert verify_password(password, hashed) is True


def test_verify_password_wrong_password_fails():
    """Verify that incorrect password fails verification."""
    password = "CorrectPassword123"
    wrong_password = "IncorrectPassword123"
    hashed = hash_password(password)

    assert verify_password(wrong_password, hashed) is False


def test_password_hashing_uses_unique_salts():
    """Verify that hashing the same password twice yields distinct hashes."""
    password = "RepeatedPassword99"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    assert hash1 != hash2
    assert verify_password(password, hash1) is True
    assert verify_password(password, hash2) is True


def test_verify_password_unicode_characters():
    """Verify that unicode characters and symbols are handled properly."""
    password = "Pässwörd!🔒_こんにちは_2026"
    hashed = hash_password(password)

    assert verify_password(password, hashed) is True
    assert verify_password("Password!_different", hashed) is False


def test_verify_password_invalid_hash_format():
    """Verify that malformed hash strings fail gracefully without crashing."""
    assert verify_password("some_password", "invalid_hash_string") is False
    assert verify_password("some_password", "") is False
    assert (
        verify_password("", "$2b$12$somevalidlengthmockhashstring1234567890123456789012") is False
    )
