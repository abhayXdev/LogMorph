"""Integration tests for Apache Kafka streaming log ingestion queue."""

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.keys import generate_api_key
from logmorph.core.security import hash_password
from logmorph.db.models import ApiKey, User
from logmorph.queue.producer import LogMorphKafkaProducer, get_kafka_producer


async def _create_test_tenant(session: AsyncSession) -> tuple[User, str]:
    """Helper to persist a user and API key in the test database."""
    user = User(
        email="kafka_test_tenant@enterprise.com",
        full_name="Kafka Ingestion Lead",
        hashed_password=hash_password("KafkaTestPass#2026"),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    key_data = generate_api_key()
    api_key = ApiKey(
        name="Kafka Stream Test Key",
        key_hash=key_data.key_hash,
        key_prefix=key_data.key_prefix,
        user_id=user.id,
    )
    session.add(api_key)
    await session.commit()

    return user, key_data.raw_key


@pytest.mark.asyncio
async def test_single_ingest_dispatches_to_queue(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify POST /api/v1/ingest produces a RawLogMessage to the streaming queue."""
    user, raw_key = await _create_test_tenant(async_db)

    # Use an isolated test producer instance
    test_producer = LogMorphKafkaProducer()
    from logmorph.main import app

    app.dependency_overrides[get_kafka_producer] = lambda: test_producer

    payload = {
        "raw_log": "<34>Oct 30 08:30:00 border-router kernel: DROP TCP 192.168.1.1:80",
        "source": "border-router",
    }
    headers = {"Authorization": f"Bearer {raw_key}"}

    response = await async_client.post("/api/v1/ingest", json=payload, headers=headers)
    assert response.status_code == 202

    data = response.json()
    assert data["status"] == "accepted"
    event_id = data["event_id"]

    # Verify message was enqueued into fallback buffer with matching tenant_id and event_id
    assert test_producer.fallback_queue.qsize() == 1
    queued = await test_producer.fallback_queue.get()
    assert queued.event_id == event_id
    assert queued.tenant_id == user.id
    assert queued.raw_log == payload["raw_log"]
    assert queued.source == payload["source"]

    app.dependency_overrides.pop(get_kafka_producer, None)


@pytest.mark.asyncio
async def test_batch_ingest_dispatches_all_to_queue(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify POST /api/v1/ingest/batch dispatches all messages with tenant_id."""
    user, raw_key = await _create_test_tenant(async_db)

    test_producer = LogMorphKafkaProducer()
    from logmorph.main import app

    app.dependency_overrides[get_kafka_producer] = lambda: test_producer

    payload = {
        "logs": [
            "Log line 1 - INFO service started",
            "Log line 2 - WARN high memory usage",
            "Log line 3 - ERROR database timeout",
        ],
        "source": "batch-daemon",
    }
    headers = {"Authorization": f"Bearer {raw_key}"}

    response = await async_client.post("/api/v1/ingest/batch", json=payload, headers=headers)
    assert response.status_code == 202

    data = response.json()
    assert data["status"] == "accepted"
    assert data["count"] == 3
    assert len(data["event_ids"]) == 3

    assert test_producer.fallback_queue.qsize() == 3
    for eid in data["event_ids"]:
        msg = await test_producer.fallback_queue.get()
        assert msg.event_id == eid
        assert msg.tenant_id == user.id
        assert msg.source == "batch-daemon"

    app.dependency_overrides.pop(get_kafka_producer, None)


@pytest.mark.asyncio
async def test_health_check_reflects_kafka_status(async_client: AsyncClient):
    """Verify GET /health includes kafka connectivity state."""
    response = await async_client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert "kafka" in data
    assert data["kafka"] in ("connected", "fallback_buffer", "unconfigured", "degraded")
