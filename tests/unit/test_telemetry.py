"""Unit tests for security telemetry and IDOR probe audit logging."""

import logging
from uuid import uuid4

import pytest

from logmorph.core.telemetry import log_idor_probe, security_logger


def test_log_idor_probe_structured_output(caplog: pytest.LogCaptureFixture):
    """Verify log_idor_probe logs warning with required IDOR telemetry fields."""
    requesting_id = uuid4()
    owner_id = uuid4()

    with caplog.at_level(logging.WARNING, logger="logmorph.security"):
        log_idor_probe(
            resource_type="LogRecord",
            resource_id="evt_test_12345",
            requesting_tenant_id=requesting_id,
            actual_owner_tenant_id=owner_id,
            action="READ",
            extra={"client_ip": "198.51.100.1"},
        )

    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.levelno == logging.WARNING
    assert record.name == "logmorph.security"
    assert "Cross-tenant resource probe detected" in record.message
    assert record.event_type == "IDOR_PROBE"
    assert record.resource_type == "LogRecord"
    assert record.resource_id == "evt_test_12345"
    assert record.action == "READ"
    assert record.requesting_tenant_id == str(requesting_id)
    assert record.actual_owner_tenant_id == str(owner_id)
    assert record.client_ip == "198.51.100.1"


def test_security_logger_instance():
    """Verify security logger is properly named."""
    assert security_logger.name == "logmorph.security"
