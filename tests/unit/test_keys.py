"""Unit tests for API key generation, hashing, and verification."""

from logmorph.core.keys import (
    API_KEY_PREFIX,
    API_KEY_TOTAL_LENGTH,
    PREFIX_DISPLAY_LENGTH,
    GeneratedApiKey,
    generate_api_key,
    hash_api_key,
    is_valid_api_key_format,
    mask_api_key,
    verify_api_key,
)


def test_generate_api_key_structure():
    """Verify that generated API keys conform to specifications."""
    api_key_data = generate_api_key()

    assert isinstance(api_key_data, GeneratedApiKey)
    assert api_key_data.raw_key.startswith(API_KEY_PREFIX)
    assert len(api_key_data.raw_key) == API_KEY_TOTAL_LENGTH
    assert len(api_key_data.key_prefix) == PREFIX_DISPLAY_LENGTH
    assert api_key_data.raw_key.startswith(api_key_data.key_prefix)
    # SHA-256 hex digest should be 64 characters long
    assert len(api_key_data.key_hash) == 64


def test_generate_api_key_uniqueness():
    """Verify that generated keys have high entropy and produce no collisions."""
    keys = {generate_api_key().raw_key for _ in range(100)}
    assert len(keys) == 100


def test_hash_api_key_deterministic():
    """Verify that hashing the same key produces consistent output."""
    raw_key = "lm_live_4f8a2b9c7d1e6f3a8b5c2d9e7f1a3b6c"
    hash1 = hash_api_key(raw_key)
    hash2 = hash_api_key(raw_key)

    assert hash1 == hash2
    assert len(hash1) == 64


def test_verify_api_key_matches():
    """Verify that valid raw key matches its calculated hash."""
    generated = generate_api_key()
    assert verify_api_key(generated.raw_key, generated.key_hash) is True


def test_verify_api_key_rejection():
    """Verify that mismatched key or hash returns False."""
    key1 = generate_api_key()
    key2 = generate_api_key()

    # Cross verification must fail
    assert verify_api_key(key1.raw_key, key2.key_hash) is False
    assert verify_api_key("invalid_key_format", key1.key_hash) is False
    assert verify_api_key(key1.raw_key, "") is False


def test_is_valid_api_key_format():
    """Verify format detection handles valid and malformed keys."""
    valid_key = "lm_live_0123456789abcdef0123456789abcdef"
    assert is_valid_api_key_format(valid_key) is True

    # Bad prefix
    assert is_valid_api_key_format("xx_live_0123456789abcdef0123456789abcdef") is False
    # Bad length (too short / too long)
    assert is_valid_api_key_format("lm_live_short") is False
    assert is_valid_api_key_format(valid_key + "extrabytes") is False
    # Non-hex characters
    assert is_valid_api_key_format("lm_live_0123456789abcdef0123456789zzzzzz") is False
    # None or non-string
    assert is_valid_api_key_format("") is False
    assert is_valid_api_key_format(None) is False  # type: ignore[arg-type]


def test_mask_api_key():
    """Verify masking utility formats prefix for dashboard display."""
    raw_key = "lm_live_4f8a2b9c7d1e6f3a8b5c2d9e7f1a3b6c"
    masked = mask_api_key(raw_key)

    assert masked == "lm_live_4f8a****"
    assert len(masked) == 16
