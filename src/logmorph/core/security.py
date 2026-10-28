"""Security utilities for password hashing and authentication."""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from passlib.context import CryptContext

from logmorph.config import settings

JWT_ALGORITHM = "HS256"

# Configure bcrypt with auto deprecation handling
_pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    """Hash a plain text password using bcrypt.

    Args:
        password: Plain text password to hash.

    Returns:
        Hashed password string with salt and algorithm identifier.
    """
    return str(_pwd_context.hash(password))


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain text password against a stored bcrypt hash.

    Args:
        plain_password: Plain text password candidate.
        hashed_password: Stored bcrypt hash.

    Returns:
        True if password matches hash, False otherwise.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return bool(_pwd_context.verify(plain_password, hashed_password))
    except Exception:
        return False


def create_access_token(
    subject: str | UUID,
    email: str,
    expires_delta: timedelta | None = None,
) -> str:
    """Create a signed JWT access token.

    Args:
        subject: Subject identifier (typically User UUID).
        email: User email address.
        expires_delta: Optional custom token expiration duration.

    Returns:
        Encoded JWT string.
    """
    now = datetime.now(UTC)
    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: dict[str, Any] = {
        "sub": str(subject),
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "token_type": "access",
    }

    return jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token.

    Args:
        token: JWT string to decode.

    Returns:
        Decoded payload dictionary.

    Raises:
        jwt.ExpiredSignatureError: If token has expired.
        jwt.InvalidTokenError: If token signature or claims are invalid.
    """
    payload = jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[JWT_ALGORITHM],
        options={"require": ["sub", "email", "exp", "iat"]},
    )

    if payload.get("token_type") != "access":
        raise jwt.InvalidTokenError("Invalid token type: expected access token")

    return payload
