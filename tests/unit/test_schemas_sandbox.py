"""Unit tests for SandboxParseRequest schema validation and payload constraints (FIX-P11)."""

import pytest
from pydantic import ValidationError

from logmorph.schemas.sandbox import SandboxParseRequest


def test_sandbox_parse_request_valid_payload():
    """Verify standard log payload within limits is accepted."""
    req = SandboxParseRequest(raw_log="Oct 11 22:14:15 host sshd: Accepted publickey")
    assert req.raw_log == "Oct 11 22:14:15 host sshd: Accepted publickey"
    assert req.format_hint is None


def test_sandbox_parse_request_exact_boundary():
    """Verify payload at exact 8192 character boundary is accepted."""
    req = SandboxParseRequest(raw_log="X" * 8192, format_hint="SYSLOG")
    assert len(req.raw_log) == 8192
    assert req.format_hint == "SYSLOG"


def test_sandbox_parse_request_oversized_payload_rejected():
    """Verify payload exceeding 8192 characters is rejected with ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        SandboxParseRequest(raw_log="X" * 8193)
    errors = exc_info.value.errors()
    assert any("at most 8192 characters" in str(err["msg"]) for err in errors)


def test_sandbox_parse_request_empty_payload_rejected():
    """Verify empty string payload is rejected with ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        SandboxParseRequest(raw_log="")
    errors = exc_info.value.errors()
    assert any("at least 1 character" in str(err["msg"]) for err in errors)


def test_sandbox_parse_request_oversized_format_hint_rejected():
    """Verify format_hint exceeding 64 characters is rejected with ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        SandboxParseRequest(raw_log="valid log", format_hint="A" * 65)
    errors = exc_info.value.errors()
    assert any("at most 64 characters" in str(err["msg"]) for err in errors)
