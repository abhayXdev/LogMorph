"""End-to-end integration tests for Ingestion Webhook -> Queue Buffer -> Format Detection."""

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.keys import generate_api_key
from logmorph.core.security import hash_password
from logmorph.db.models import ApiKey, User
from logmorph.domain.uls import LogFormatEnum
from logmorph.engine.detector import detect_format
from logmorph.main import app
from logmorph.queue.producer import LogMorphKafkaProducer, get_kafka_producer
from tests.fixtures.loader import load_fixture_lines, load_ground_truth_corpus


async def _create_test_tenant(
    session: AsyncSession,
    email: str = "pipeline_tenant@logmorph.io",
    name: str = "Pipeline Tenant",
) -> tuple[User, str]:
    """Helper to create and persist a test tenant and API key."""
    user = User(
        email=email,
        full_name=name,
        hashed_password=hash_password("PipelinePass#2026"),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    key_data = generate_api_key()
    api_key = ApiKey(
        name=f"{name} Key",
        key_hash=key_data.key_hash,
        key_prefix=key_data.key_prefix,
        user_id=user.id,
    )
    session.add(api_key)
    await session.commit()

    return user, key_data.raw_key


@pytest.mark.asyncio
async def test_single_ingest_detect_pipeline_all_formats(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify that every supported log format is ingested, queued, and detected correctly."""
    user, raw_key = await _create_test_tenant(async_db)

    test_producer = LogMorphKafkaProducer()
    app.dependency_overrides[get_kafka_producer] = lambda: test_producer

    headers = {"X-API-Key": raw_key}
    corpus = load_ground_truth_corpus()

    try:
        for expected_format, samples in corpus.items():
            sample_line = samples[0]

            response = await async_client.post(
                "/api/v1/ingest",
                json={"raw_log": sample_line, "source": f"collector-{expected_format.lower()}"},
                headers=headers,
            )
            assert response.status_code == 202
            resp_data = response.json()
            assert resp_data["status"] == "accepted"
            event_id = resp_data["event_id"]

            # Drain from queue buffer
            assert not test_producer.fallback_queue.empty()
            message = test_producer.fallback_queue.get_nowait()

            assert message.event_id == event_id
            assert message.tenant_id == user.id
            assert message.raw_log == sample_line

            # Execute format detection stage on the queued message
            detection = detect_format(message.raw_log)
            assert detection.detected_format == expected_format, (
                f"Detection mismatch for {expected_format}: "
                f"got {detection.detected_format} (confidence {detection.confidence})"
            )
            assert detection.confidence > 0.0

    finally:
        app.dependency_overrides.pop(get_kafka_producer, None)


@pytest.mark.asyncio
async def test_heterogeneous_batch_ingest_detect_pipeline(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify that a batch with mixed log formats is queued and classified accurately."""
    user, raw_key = await _create_test_tenant(
        async_db,
        email="batch_tenant@logmorph.io",
        name="Batch Tenant",
    )

    test_producer = LogMorphKafkaProducer()
    app.dependency_overrides[get_kafka_producer] = lambda: test_producer

    headers = {"Authorization": f"Bearer {raw_key}"}

    # Build a heterogeneous batch: one line from each format
    batch_specs: list[tuple[LogFormatEnum, str]] = [
        (LogFormatEnum.SYSLOG, load_fixture_lines("syslog_rfc5424.log")[0]),
        (LogFormatEnum.SYSLOG, load_fixture_lines("syslog_rfc3164.log")[0]),
        (LogFormatEnum.CLF, load_fixture_lines("apache_clf.log")[0]),
        (LogFormatEnum.CEF, load_fixture_lines("cef_events.log")[0]),
        (LogFormatEnum.LEEF, load_fixture_lines("leef_events.log")[0]),
        (LogFormatEnum.JSON, load_fixture_lines("json_events.jsonl")[0]),
        (LogFormatEnum.XML, load_fixture_lines("xml_events.log")[0]),
        (LogFormatEnum.UNSTRUCTURED, load_fixture_lines("unstructured.log")[0]),
    ]

    raw_batch = [line for _, line in batch_specs]

    try:
        response = await async_client.post(
            "/api/v1/ingest/batch",
            json={"logs": raw_batch, "source": "heterogeneous-agent"},
            headers=headers,
        )
        assert response.status_code == 202
        data = response.json()
        assert data["count"] == len(batch_specs)
        event_ids = data["event_ids"]

        # Drain and classify all batch items in order
        assert test_producer.fallback_queue.qsize() == len(batch_specs)

        for idx, (expected_fmt, raw_log) in enumerate(batch_specs):
            msg = test_producer.fallback_queue.get_nowait()
            assert msg.event_id == event_ids[idx]
            assert msg.tenant_id == user.id
            assert msg.raw_log == raw_log

            detection = detect_format(msg.raw_log)
            assert detection.detected_format == expected_fmt, (
                f"Batch item {idx} mismatch: expected {expected_fmt}, got {detection.detected_format}"
            )

    finally:
        app.dependency_overrides.pop(get_kafka_producer, None)


@pytest.mark.asyncio
async def test_multi_tenant_ingest_detection_isolation(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify multi-tenant isolation where messages from distinct tenants stay strictly isolated."""
    tenant_a, key_a = await _create_test_tenant(
        async_db,
        email="tenant_a@logmorph.io",
        name="Tenant Alpha",
    )
    tenant_b, key_b = await _create_test_tenant(
        async_db,
        email="tenant_b@logmorph.io",
        name="Tenant Beta",
    )

    test_producer = LogMorphKafkaProducer()
    app.dependency_overrides[get_kafka_producer] = lambda: test_producer

    log_a = '{"service": "alpha-auth", "event": "login_ok"}'
    log_b = "CEF:0|Vendor|App|1.0|200|Allowed|3|src=10.0.0.1"

    try:
        # Ingest for Tenant A
        res_a = await async_client.post(
            "/api/v1/ingest",
            json={"raw_log": log_a},
            headers={"X-API-Key": key_a},
        )
        assert res_a.status_code == 202

        # Ingest for Tenant B
        res_b = await async_client.post(
            "/api/v1/ingest",
            json={"raw_log": log_b},
            headers={"X-API-Key": key_b},
        )
        assert res_b.status_code == 202

        # Drain messages
        msg_a = test_producer.fallback_queue.get_nowait()
        msg_b = test_producer.fallback_queue.get_nowait()

        # Strict tenant verification
        assert msg_a.tenant_id == tenant_a.id
        assert msg_a.tenant_id != tenant_b.id
        assert detect_format(msg_a.raw_log).detected_format == LogFormatEnum.JSON

        assert msg_b.tenant_id == tenant_b.id
        assert msg_b.tenant_id != tenant_a.id
        assert detect_format(msg_b.raw_log).detected_format == LogFormatEnum.CEF

    finally:
        app.dependency_overrides.pop(get_kafka_producer, None)


@pytest.mark.asyncio
async def test_empty_and_whitespace_batch_elements_rejection(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify that malformed batches are rejected before reaching the streaming buffer."""
    _, key = await _create_test_tenant(
        async_db,
        email="validator_tenant@logmorph.io",
        name="Validator Tenant",
    )

    test_producer = LogMorphKafkaProducer()
    app.dependency_overrides[get_kafka_producer] = lambda: test_producer

    try:
        response = await async_client.post(
            "/api/v1/ingest/batch",
            json={"logs": ["valid log line", "   \t\n  "]},
            headers={"X-API-Key": key},
        )
        assert response.status_code == 422
        # Buffer remains empty
        assert test_producer.fallback_queue.empty()

    finally:
        app.dependency_overrides.pop(get_kafka_producer, None)
