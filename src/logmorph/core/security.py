"""Security utilities for password hashing and authentication."""

from passlib.context import CryptContext

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
    return _pwd_context.hash(password)


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
