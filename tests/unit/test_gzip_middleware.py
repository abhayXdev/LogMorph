"""Unit tests for safe_gzip_decompress and GzipRequestMiddleware (FIX-P7)."""

import gzip

import pytest

from logmorph.middleware.gzip_request import safe_gzip_decompress


def test_safe_gzip_decompress_valid_payload():
    """Verify normal gzip decompression reproduces original bytes."""
    original = b"This is a sample log line for testing"
    compressed = gzip.compress(original)
    decompressed = safe_gzip_decompress(compressed)
    assert decompressed == original


def test_safe_gzip_decompress_traversal_attack_string():
    """Verify directory traversal string is cleanly decompressed."""
    original = b'{"raw_log": "../../etc/passwd attempted by root", "source": "honeypot"}'
    compressed = gzip.compress(original)
    decompressed = safe_gzip_decompress(compressed)
    assert decompressed == original
    assert b"../../etc/passwd" in decompressed


def test_safe_gzip_decompress_corrupted_input():
    """Verify corrupted non-gzip bytes raise BadGzipFile or OSError."""
    with pytest.raises((gzip.BadGzipFile, OSError)):
        safe_gzip_decompress(b"not a valid gzip header")


def test_safe_gzip_decompress_decompression_bomb_protection():
    """Verify exceeding max_size raises ValueError to prevent memory exhaustion."""
    large_payload = b"A" * 5000
    compressed = gzip.compress(large_payload)
    with pytest.raises(ValueError) as exc_info:
        safe_gzip_decompress(compressed, max_size=2000)
    assert "exceeded maximum limit" in str(exc_info.value)
