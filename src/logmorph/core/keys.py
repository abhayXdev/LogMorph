"""API Key generation, hashing, and verification utilities."""

import hashlib
import hmac
import re
import secrets
from typing import NamedTuple

API_KEY_PREFIX = "lm_live_"
API_KEY_RANDOM_BYTES = 16  # Produces 32 hex chars
API_KEY_TOTAL_LENGTH = len(API_KEY_PREFIX) + (API_KEY_RANDOM_BYTES * 2)  # 8 + 32 = 40
PREFIX_DISPLAY_LENGTH = 12

_API_KEY_PATTERN = re.compile(r"^lm_live_[0-9a-fA-F]{32}$")


class GeneratedApiKey(NamedTuple):
    """Result of generating a new API key."""

    raw_key: str
    key_prefix: str
    key_hash: str


def generate_api_key() -> GeneratedApiKey:
    """Generate a new cryptographically secure API key.

    Returns:
        GeneratedApiKey containing:
        - raw_key: Full API key (e.g. 'lm_live_4f8a2b9c7d1e6f3a8b5c2d9e7f1a3b6c')
        - key_prefix: First 12 characters for display/lookup (e.g. 'lm_live_4f8a')
        - key_hash: SHA-256 hex digest for persistent secure storage
    """
    random_hex = secrets.token_hex(API_KEY_RANDOM_BYTES)
    raw_key = f"{API_KEY_PREFIX}{random_hex}"
    key_prefix = raw_key[:PREFIX_DISPLAY_LENGTH]
    key_hash = hash_api_key(raw_key)

    return GeneratedApiKey(
        raw_key=raw_key,
        key_prefix=key_prefix,
        key_hash=key_hash,
    )


def hash_api_key(raw_key: str) -> str:
    """Compute one-way SHA-256 digest of a raw API key for storage.

    Args:
        raw_key: Plain text API key string.

    Returns:
        Hex-encoded SHA-256 hash.
    """
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def verify_api_key(raw_key: str, expected_hash: str) -> bool:
    """Verify raw API key against stored hash using constant-time comparison.

    Args:
        raw_key: Candidate API key provided by client.
        expected_hash: Stored SHA-256 hash from database.

    Returns:
        True if the candidate key matches the expected hash, False otherwise.
    """
    if not is_valid_api_key_format(raw_key) or not expected_hash:
        return False

    candidate_hash = hash_api_key(raw_key)
    return hmac.compare_digest(candidate_hash, expected_hash)


def is_valid_api_key_format(raw_key: str) -> bool:
    """Check whether a string matches the required API key structure.

    Args:
        raw_key: Candidate string to inspect.

    Returns:
        True if format is valid, False otherwise.
    """
    if not isinstance(raw_key, str) or len(raw_key) != API_KEY_TOTAL_LENGTH:
        return False
    return bool(_API_KEY_PATTERN.match(raw_key))


def mask_api_key(raw_or_prefix: str) -> str:
    """Format key prefix for safe dashboard presentation (e.g. 'lm_live_4f8a****').

    Args:
        raw_or_prefix: Full key or 12-char prefix.

    Returns:
        Masked string with trailing asterisks.
    """
    prefix = raw_or_prefix[:PREFIX_DISPLAY_LENGTH]
    return f"{prefix}****"
