"""Unit tests for JWT authentication token creation and validation."""

from datetime import timedelta
from uuid import uuid4

import jwt
import pytest

from logmorph.config import settings
from logmorph.core.security import JWT_ALGORITHM, create_access_token, decode_access_token


def test_create_and_decode_access_token_with_uuid():
    """Verify that a token created with UUID subject decodes accurately."""
    user_id = uuid4()
    email = "security_lead@example.com"

    token = create_access_token(subject=user_id, email=email)
    assert isinstance(token, str)

    payload = decode_access_token(token)
    assert payload["sub"] == str(user_id)
    assert payload["email"] == email
    assert payload["token_type"] == "access"
    assert "iat" in payload
    assert "exp" in payload
    assert payload["exp"] > payload["iat"]


def test_create_and_decode_access_token_with_string_subject():
    """Verify token creation with a string identifier."""
    token = create_access_token(subject="usr_tenant_alpha", email="alpha@tenant.io")
    payload = decode_access_token(token)

    assert payload["sub"] == "usr_tenant_alpha"
    assert payload["email"] == "alpha@tenant.io"


def test_custom_expiration_delta():
    """Verify token respects a custom expiration duration."""
    custom_delta = timedelta(hours=2)
    token = create_access_token(
        subject="usr_temp",
        email="temp@example.com",
        expires_delta=custom_delta,
    )
    payload = decode_access_token(token)

    # Expiration should be approximately 2 hours (7200 seconds) after iat
    diff = payload["exp"] - payload["iat"]
    assert 7195 <= diff <= 7205


def test_expired_token_raises_expired_signature_error():
    """Verify that an expired token raises ExpiredSignatureError."""
    past_delta = timedelta(seconds=-10)
    token = create_access_token(
        subject="usr_expired",
        email="expired@example.com",
        expires_delta=past_delta,
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_tampered_token_signature_fails():
    """Verify that modifying token payload or signature fails validation."""
    token = create_access_token(subject="usr_valid", email="user@example.com")
    parts = token.split(".")
    # Tamper with the payload part
    tampered_token = f"{parts[0]}.eyJob2dndXBhZCI6IHRydWV9.{parts[2]}"

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(tampered_token)


def test_token_signed_with_different_secret_fails():
    """Verify that token signed with an unauthorized secret key is rejected."""
    unauthorized_payload = {
        "sub": "usr_hacker",
        "email": "hacker@evil.com",
        "exp": 9999999999,
        "iat": 1000000000,
        "token_type": "access",
    }
    # Key must be >= 32 bytes to satisfy RFC 7518 security recommendations
    bogus_key = "unauthorized_secret_key_exceeding_32_bytes_security"
    bogus_token = jwt.encode(unauthorized_payload, bogus_key, algorithm=JWT_ALGORITHM)

    with pytest.raises(jwt.InvalidSignatureError):
        decode_access_token(bogus_token)


def test_token_with_invalid_token_type_rejected():
    """Verify that non-access tokens (e.g. refresh) are rejected by decode_access_token."""
    payload = {
        "sub": "usr_test",
        "email": "user@example.com",
        "exp": 9999999999,
        "iat": 1000000000,
        "token_type": "refresh",
    }
    refresh_token = jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)

    with pytest.raises(jwt.InvalidTokenError, match="expected access token"):
        decode_access_token(refresh_token)
