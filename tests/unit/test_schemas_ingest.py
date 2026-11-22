"""Unit tests for IngestRequest and BatchIngestRequest schema validation and NUL byte sanitization."""

import pytest
from pydantic import ValidationError

from logmorph.schemas.ingest import BatchIngestRequest, IngestRequest


def test_ingest_request_sanitizes_nul_bytes():
    """Verify that IngestRequest strips NUL bytes (0x00) from raw_log."""
    payload = IngestRequest(raw_log="Syslog header \x00 attack payload after null")
    assert payload.raw_log == "Syslog header  attack payload after null"
    assert "\x00" not in payload.raw_log


def test_ingest_request_pure_nul_bytes_rejected():
    """Verify that IngestRequest rejects a raw_log containing only NUL bytes."""
    with pytest.raises(ValidationError) as exc_info:
        IngestRequest(raw_log="\x00\x00\x00")
    errors = exc_info.value.errors()
    assert any("raw_log must contain non-whitespace characters" in str(err["msg"]) for err in errors)


def test_batch_ingest_request_sanitizes_nul_bytes():
    """Verify that BatchIngestRequest strips NUL bytes from all batch log items."""
    batch = BatchIngestRequest(logs=[
        "Normal log line 1",
        "Corrupted \x00 memory dump \x00 payload",
        "Normal log line 3",
    ])
    assert batch.logs[0] == "Normal log line 1"
    assert batch.logs[1] == "Corrupted  memory dump  payload"
    assert "\x00" not in batch.logs[1]
    assert batch.logs[2] == "Normal log line 3"


def test_batch_ingest_request_pure_nul_item_rejected():
    """Verify that BatchIngestRequest rejects a batch item containing only NUL bytes."""
    with pytest.raises(ValidationError) as exc_info:
        BatchIngestRequest(logs=["Valid line", "\x00\x00\x00"])
    errors = exc_info.value.errors()
    assert any("must contain non-whitespace characters" in str(err["msg"]) for err in errors)
