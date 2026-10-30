"""Unit tests for Apache Kafka message schema and producer service."""

import os
import uuid
from datetime import UTC, datetime

import pytest

from logmorph.config import settings
from logmorph.queue.producer import LogMorphKafkaProducer
from logmorph.schemas.queue import RawLogMessage


def test_raw_log_message_schema_validation():
    """Verify RawLogMessage instantiation, field types, and default timestamps."""
    event_id = f"evt_{uuid.uuid4()}"
    tenant_id = uuid.uuid4()
    raw_log = "<34>Oct 30 08:00:00 server syslog: user logged in"
    source = "syslog-collector"

    message = RawLogMessage(
        event_id=event_id,
        tenant_id=tenant_id,
        raw_log=raw_log,
        source=source,
    )

    assert message.event_id == event_id
    assert message.tenant_id == tenant_id
    assert message.raw_log == raw_log
    assert message.source == source
    assert isinstance(message.ingested_at, datetime)
    assert message.ingested_at.tzinfo == UTC


def test_raw_log_message_json_serialization():
    """Verify RawLogMessage JSON serialization formats UUID and datetime properly."""
    message = RawLogMessage(
        event_id="evt_12345",
        tenant_id=uuid.UUID("11111111-2222-3333-4444-555555555555"),
        raw_log="test log line",
    )
    dumped = message.model_dump(mode="json")
    assert dumped["event_id"] == "evt_12345"
    assert dumped["tenant_id"] == "11111111-2222-3333-4444-555555555555"
    assert isinstance(dumped["ingested_at"], str)


@pytest.mark.asyncio
async def test_producer_fallback_queue_on_single_log():
    """Verify that when not connected to a broker, producer queues to fallback buffer."""
    producer = LogMorphKafkaProducer()
    assert producer.is_connected is False
    assert producer.fallback_queue.empty() is True

    message = RawLogMessage(
        event_id="evt_test_fallback",
        tenant_id=uuid.uuid4(),
        raw_log="fallback log test",
    )

    success = await producer.send_log(message)
    assert success is True
    assert producer.fallback_queue.qsize() == 1

    queued_msg = await producer.fallback_queue.get()
    assert queued_msg.event_id == "evt_test_fallback"
    assert queued_msg.raw_log == "fallback log test"


@pytest.mark.asyncio
async def test_producer_fallback_queue_on_batch_logs():
    """Verify batch ingestion routes all items to fallback queue when broker is inactive."""
    producer = LogMorphKafkaProducer()
    tenant_id = uuid.uuid4()

    messages = [
        RawLogMessage(
            event_id=f"evt_batch_{i}",
            tenant_id=tenant_id,
            raw_log=f"batch log line {i}",
        )
        for i in range(5)
    ]

    count = await producer.send_batch(messages)
    assert count == 5
    assert producer.fallback_queue.qsize() == 5

    for i in range(5):
        msg = await producer.fallback_queue.get()
        assert msg.event_id == f"evt_batch_{i}"


def test_ssl_context_building_with_cafile():
    """Verify that _build_ssl_context parses valid cafile if present."""
    producer = LogMorphKafkaProducer()
    cafile = "certs/ca.pem"
    if os.path.exists(cafile):
        ctx = producer._build_ssl_context()
        assert ctx is not None
