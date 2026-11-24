"""End-to-end integration tests for Ingestion Webhook -> Queue Buffer -> 3-Tier Parsing Cascade."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.config import settings
from logmorph.core.keys import generate_api_key
from logmorph.core.security import hash_password
from logmorph.db.models import ApiKey, User
from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum
from logmorph.engine.parsers.nim_client import (
    close_nim_client,
    get_circuit_breaker,
)
from logmorph.engine.parsers.orchestrator import (
    get_cascade_metrics,
    parse_cascade_async,
)
from logmorph.main import app
from logmorph.queue.producer import LogMorphKafkaProducer, get_kafka_producer
from tests.fixtures.loader import load_fixture_lines, load_ground_truth_corpus


@pytest.fixture(autouse=True)
async def isolate_integration_environment():
    """Ensure Redis is disabled, and reset circuit breaker, client, and metrics."""
    with patch.object(settings, "REDIS_URL", None):
        metrics = get_cascade_metrics()
        metrics.reset()
        cb = get_circuit_breaker()
        await cb.reset()
        await close_nim_client()
        yield
        metrics.reset()
        await cb.reset()
        await close_nim_client()


async def _create_test_tenant(
    session: AsyncSession,
    email: str = "cascade_tenant@logmorph.io",
    name: str = "Cascade Tenant",
) -> tuple[User, str]:
    """Helper to create and persist a test tenant and API key."""
    user = User(
        email=email,
        full_name=name,
        hashed_password=hash_password("CascadePass#2026"),
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


class TestGoldenCorpusCascadePipeline:
    """Scenario 1: Full Golden Corpus End-to-End Pipeline Verification."""

    @pytest.mark.asyncio
    async def test_single_ingest_and_cascade_all_golden_formats(
        self,
        async_client: AsyncClient,
        async_db: AsyncSession,
    ):
        """Verify that every golden log format is ingested, queued, and normalized through the cascade."""
        user, raw_key = await _create_test_tenant(async_db)
        test_producer = LogMorphKafkaProducer()
        app.dependency_overrides[get_kafka_producer] = lambda: test_producer

        headers = {"X-API-Key": raw_key}
        corpus = load_ground_truth_corpus()

        # Mock LLM for novel unstructured logs
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "action": "system_event",
            "severity": "ERROR",
            "summary": "Normalized unstructured log event",
            "attributes": {"pipeline": "e2e_integration"},
        })
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        try:
            with (
                patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
                patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
            ):
                for expected_format, samples in corpus.items():
                    sample_line = samples[0]

                    # 1. Ingest via API
                    response = await async_client.post(
                        "/api/v1/ingest",
                        json={"raw_log": sample_line, "source": f"collector-{expected_format.lower()}"},
                        headers=headers,
                    )
                    assert response.status_code == 202
                    resp_data = response.json()
                    assert resp_data["status"] == "accepted"
                    event_id = resp_data["event_id"]

                    # 2. Drain from Queue Buffer
                    assert not test_producer.fallback_queue.empty()
                    message = test_producer.fallback_queue.get_nowait()
                    assert message.event_id == event_id
                    assert message.tenant_id == user.id

                    # 3. Process via 3-Tier Cascade Orchestrator
                    result = await parse_cascade_async(message.raw_log, tenant_id=message.tenant_id)

                    assert result.success is True
                    assert result.attributes.get("cascade_tier") is not None
                    assert "tier_latencies_ms" in result.attributes
                    assert "cascade_total_latency_ms" in result.attributes

                    if expected_format != LogFormatEnum.UNSTRUCTURED:
                        # Structured logs must resolve via Tier 1
                        assert result.parsed_by == ParsingTierEnum.RULE
                        assert result.confidence == 1.0
                        assert result.format == expected_format
                        assert result.attributes["cascade_route"] == ["TIER_1"]
                    else:
                        # Unstructured logs must escalate beyond Tier 1
                        assert result.parsed_by in {ParsingTierEnum.TEMPLATE, ParsingTierEnum.LLM}
                        assert "TIER_2" in result.attributes["cascade_route"]
        finally:
            app.dependency_overrides.pop(get_kafka_producer, None)

    @pytest.mark.asyncio
    async def test_unstructured_golden_corpus_semantic_extraction(self):
        """Verify that all unstructured fixture logs parse through Tier 2 and Tier 3."""
        unstructured_lines = load_fixture_lines("unstructured.log")
        tenant_id = "00000000-0000-0000-0000-000000000001"

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "action": "application_failure",
            "severity": "CRITICAL",
            "summary": "Critical runtime failure detected",
            "attributes": {"framework": "jvm"},
        })
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            for raw_log in unstructured_lines:
                result = await parse_cascade_async(raw_log, tenant_id=tenant_id)
                assert result.success is True
                assert result.parsed_by in {ParsingTierEnum.TEMPLATE, ParsingTierEnum.LLM}
                assert result.confidence >= 0.50
                assert "template" in result.attributes


class TestCascadeTemplateConvergenceLifecycle:
    """Scenario 2: Dynamic Template Convergence (The 3-Tier Lifecycle)."""

    @pytest.mark.asyncio
    async def test_novel_log_converges_to_tier2_on_repeat(self):
        """Verify that novel logs transition from Tier 3 LLM to microsecond Tier 2 template hits."""
        tenant_id = "00000000-0000-0000-0000-000000000002"
        metrics = get_cascade_metrics()
        metrics.reset()

        # Event 1: Novel pattern
        log_event_1 = "com.corp.AuthFailedException: invalid token for user admin from 10.0.0.1 on port 443"
        # Event 2: Repeat pattern with different user and IP
        log_event_2 = "com.corp.AuthFailedException: invalid token for user bob from 10.0.0.2 on port 443"
        # Event 3: Third occurrence with another user
        log_event_3 = "com.corp.AuthFailedException: invalid token for user charlie from 10.0.0.3 on port 443"

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "action": "auth_failure",
            "severity": "WARNING",
            "user": "admin",
            "summary": "Authentication failure with invalid token",
            "attributes": {"auth_type": "bearer_token"},
        })
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            # Stream Event 1: First observation -> escalates to Tier 3 LLM
            res1 = await parse_cascade_async(log_event_1, tenant_id=tenant_id)
            assert res1.success is True
            assert res1.parsed_by == ParsingTierEnum.LLM
            assert res1.confidence == 0.85
            assert res1.attributes["cascade_route"] == ["TIER_1", "TIER_2", "TIER_3"]
            assert mock_client.chat.completions.create.call_count == 1

            # Stream Event 2: Second observation -> template generalizes -> TERMINATES AT TIER 2
            res2 = await parse_cascade_async(log_event_2, tenant_id=tenant_id)
            assert res2.success is True
            assert res2.parsed_by == ParsingTierEnum.TEMPLATE
            assert res2.confidence == 0.75  # cluster_template_changed confidence >= 0.70
            assert res2.attributes["cascade_route"] == ["TIER_1", "TIER_2"]
            assert "TIER_3" not in res2.attributes["cascade_route"]
            # LLM call count must remain 1 (zero calls made for Event 2!)
            assert mock_client.chat.completions.create.call_count == 1

            # Stream Event 3: Third observation -> continues terminating at Tier 2
            res3 = await parse_cascade_async(log_event_3, tenant_id=tenant_id)
            assert res3.success is True
            assert res3.parsed_by == ParsingTierEnum.TEMPLATE
            assert res3.confidence == 0.90
            assert res3.attributes["cascade_route"] == ["TIER_1", "TIER_2"]
            assert mock_client.chat.completions.create.call_count == 1

            # Metrics audit: 1 Tier 3 hit, 2 Tier 2 hits
            snap = metrics.get_metrics()
            assert snap["tier3_hits"] == 1
            assert snap["tier2_hits"] == 2
            assert snap["tier1_hits"] == 0
            assert snap["total_processed"] == 3


class TestMultiTenantCascadeStreamIsolation:
    """Scenario 3: Multi-Tenant Stream Interleaving & Cluster Isolation."""

    @pytest.mark.asyncio
    async def test_interleaved_multi_tenant_streams_maintain_isolation(
        self,
        async_db: AsyncSession,
    ):
        """Verify that Tenant A and Tenant B maintain strictly separated Drain3 cluster trees."""
        tenant_a, _ = await _create_test_tenant(async_db, email="tenant_a@corp.com", name="Tenant A")
        tenant_b, _ = await _create_test_tenant(async_db, email="tenant_b@corp.com", name="Tenant B")

        # Distinct log formats unique to each tenant
        logs_a = [
            f"TenantA.BillingService: invoice generated for order {1000 + i}"
            for i in range(5)
        ]
        logs_b = [
            f"TenantB.InventoryService: stock depleted for sku {5000 + i}"
            for i in range(5)
        ]

        # Interleave streams: [A0, B0, A1, B1, A2, B2, ...]
        interleaved_stream = []
        for la, lb in zip(logs_a, logs_b, strict=False):
            interleaved_stream.append((tenant_a.id, la))
            interleaved_stream.append((tenant_b.id, lb))

        with patch.object(settings, "NVIDIA_NIM_API_KEY", None):
            # Run without LLM: first event will fall back, repeat events will converge in Tier 2
            results_a = []
            results_b = []

            for tid, raw_log in interleaved_stream:
                res = await parse_cascade_async(raw_log, tenant_id=tid)
                if tid == tenant_a.id:
                    results_a.append(res)
                else:
                    results_b.append(res)

            # Assert Tenant A converged on its own template
            template_a = results_a[-1].attributes.get("template")
            assert "BillingService" in str(template_a)
            assert "InventoryService" not in str(template_a)
            assert results_a[-1].parsed_by == ParsingTierEnum.TEMPLATE
            assert results_a[-1].confidence == 0.90

            # Assert Tenant B converged on its own template
            template_b = results_b[-1].attributes.get("template")
            assert "InventoryService" in str(template_b)
            assert "BillingService" not in str(template_b)
            assert results_b[-1].parsed_by == ParsingTierEnum.TEMPLATE
            assert results_b[-1].confidence == 0.90

            # Assert cluster trees are disjoint
            assert template_a != template_b
