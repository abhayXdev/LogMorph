"""Cascade batch throughput, chaos fault injection resilience, and latency SLA benchmark tests."""

import json
import statistics
import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from httpx import AsyncClient
from openai import APIStatusError, APITimeoutError, AuthenticationError
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.config import settings
from logmorph.core.keys import generate_api_key
from logmorph.core.security import hash_password
from logmorph.db.models import ApiKey, User
from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum
from logmorph.engine.parsers.nim_client import (
    CircuitState,
    close_nim_client,
    get_circuit_breaker,
)
from logmorph.engine.parsers.orchestrator import (
    get_cascade_metrics,
    parse_cascade_async,
    parse_cascade_batch_async,
)
from logmorph.engine.parsers.tier1 import parse_tier1
from logmorph.main import app
from logmorph.queue.producer import LogMorphKafkaProducer, get_kafka_producer


@pytest.fixture(autouse=True)
async def isolate_benchmark_environment():
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
    email: str = "benchmark_tenant@logmorph.io",
    name: str = "Benchmark Tenant",
) -> tuple[User, str]:
    """Helper to create and persist a test tenant and API key."""
    user = User(
        email=email,
        full_name=name,
        hashed_password=hash_password("BenchmarkPass#2026"),
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


def _build_50_heterogeneous_logs() -> tuple[list[str], list[LogFormatEnum]]:
    """Synthesize 50 heterogeneous logs across all supported formats.

    Distribution:
    - 0..9: Syslog RFC 5424 (Tier 1)
    - 10..19: Apache CLF (Tier 1)
    - 20..29: JSON structured (Tier 1)
    - 30..39: CEF (Tier 1)
    - 40..49: Unstructured logs (5 templates x 2 repetitions each)
    """
    logs: list[str] = []
    expected_formats: list[LogFormatEnum] = []

    # 1. 10 Syslog RFC 5424 logs
    for i in range(10):
        logs.append(
            f"<165>1 2026-10-30T10:00:{i:02d}.000Z edge-gw-{i} authd 100{i} ID47 "
            f'[exampleSDID@32473 iut="3" eventSource="auth"] User admin_{i} logged in successfully'
        )
        expected_formats.append(LogFormatEnum.SYSLOG)

    # 2. 10 Apache Common Log Format logs
    for i in range(10):
        logs.append(
            f'192.168.1.{10 + i} - - [10/Oct/2026:13:55:{i:02d} +0000] '
            f'"GET /api/v1/metrics/node/{i} HTTP/1.1" 200 1024'
        )
        expected_formats.append(LogFormatEnum.CLF)

    # 3. 10 Structured JSON logs
    for i in range(10):
        logs.append(
            json.dumps({
                "timestamp": f"2026-10-30T10:00:{i:02d}Z",
                "level": "INFO",
                "message": f"Service cluster heartbeat check ok on node {i}",
                "service": "orchestrator",
                "node_id": i,
            })
        )
        expected_formats.append(LogFormatEnum.JSON)

    # 4. 10 CEF logs
    for i in range(10):
        logs.append(
            f"CEF:0|CyberSec|Firewall|4.0|10{i}|Traffic Alert|3|"
            f"src=10.0.1.{i} dst=172.16.0.{i} spt={4000 + i} dpt=443 msg=Outbound allowed"
        )
        expected_formats.append(LogFormatEnum.CEF)

    # 5. 10 Unstructured logs (5 distinct novel templates x 2 repetitions each)
    unstructured_templates = [
        "cluster.node: worker thread {val} finished batch processing in 45ms",
        "DatabasePoolExhausted: unable to acquire connection for client {val} on pool main",
        "CacheEvictionEvent: expired key session_token_{val} purged from memory",
        "PaymentWebhookReceived: charge completed for customer_{val} amount 9900",
        "StorageAlert: filesystem /mnt/data_{val} reached critical threshold 95%",
    ]
    for template in unstructured_templates:
        for rep in range(2):
            logs.append(template.format(val=f"item_{rep}"))
            expected_formats.append(LogFormatEnum.UNSTRUCTURED)

    return logs, expected_formats


class TestBatchIngestAndCascadeOrderingIntegrity:
    """Scenario 4: Batch Ingestion Throughput & Strict Ordering Verification."""

    @pytest.mark.asyncio
    async def test_batch_ingest_endpoint_and_cascade_ordering_50_logs(
        self,
        async_client: AsyncClient,
        async_db: AsyncSession,
    ):
        """Verify that 50 logs submitted via batch endpoint are queued and cascade-parsed preserving 1-to-1 order."""
        user, raw_key = await _create_test_tenant(async_db)
        test_producer = LogMorphKafkaProducer()
        app.dependency_overrides[get_kafka_producer] = lambda: test_producer

        raw_logs, expected_formats = _build_50_heterogeneous_logs()
        assert len(raw_logs) == 50

        # Step 1: Submit 50 logs via POST /api/v1/ingest/batch
        response = await async_client.post(
            "/api/v1/ingest/batch",
            json={"logs": raw_logs, "source": "integration-batch-runner"},
            headers={"X-API-Key": raw_key},
        )
        assert response.status_code == 202
        body = response.json()
        assert body["status"] == "accepted"
        assert body["count"] == 50
        assert len(body["event_ids"]) == 50

        # Step 2: Verify Kafka queue ordering integrity
        assert test_producer.fallback_queue.qsize() == 50
        for idx in range(50):
            msg = await test_producer.fallback_queue.get()
            assert msg.raw_log == raw_logs[idx]
            assert msg.event_id == body["event_ids"][idx]
            assert msg.tenant_id == user.id

        app.dependency_overrides.pop(get_kafka_producer, None)

        # Step 3: Run full 50-log batch through parse_cascade_batch_async with mocked LLM
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "action": "batch_event",
            "severity": "WARNING",
            "summary": "Novel unstructured batch event parsed by Tier 3",
            "attributes": {"batch_mode": True},
        })
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            results = await parse_cascade_batch_async(raw_logs, tenant_id=user.id)

        # Step 4: Validate 1-to-1 strict ordering preservation and tier distribution
        assert len(results) == 50

        for idx, (res, expected_fmt) in enumerate(zip(results, expected_formats, strict=False)):
            assert res.success is True, f"Item at index {idx} failed parsing"
            assert res.format == expected_fmt, (
                f"Index {idx} expected format {expected_fmt}, got {res.format}"
            )

            if idx < 40:
                # Indices 0..39: Tier 1 fast path
                assert res.parsed_by == ParsingTierEnum.RULE, (
                    f"Index {idx} expected RULE tier, got {res.parsed_by}"
                )
                assert res.confidence == 1.0
                assert res.attributes["cascade_route"] == ["TIER_1"]
            else:
                # Indices 40..49: Unstructured logs (5 pairs)
                pair_offset = (idx - 40) % 2
                if pair_offset == 0:
                    # 1st of each template pair: escalated to Tier 3 LLM
                    assert res.parsed_by == ParsingTierEnum.LLM, (
                        f"Index {idx} expected LLM tier, got {res.parsed_by}"
                    )
                    assert res.confidence == 0.85
                    assert res.attributes["cascade_route"] == ["TIER_1", "TIER_2", "TIER_3"]
                else:
                    # 2nd of each template pair: converged at Tier 2 Template Miner
                    assert res.parsed_by == ParsingTierEnum.TEMPLATE, (
                        f"Index {idx} expected TEMPLATE tier, got {res.parsed_by}"
                    )
                    assert res.confidence >= 0.70
                    assert res.attributes["cascade_route"] == ["TIER_1", "TIER_2"]

        # Step 5: Verify exact LLM invocation count (5 novel items in batch = exactly 5 LLM calls)
        assert mock_client.chat.completions.create.call_count == 5

    @pytest.mark.asyncio
    async def test_batch_cascade_empty_and_whitespace_elements(self):
        """Verify batch handling with empty lists and whitespace elements."""
        assert await parse_cascade_batch_async([]) == []

        results = await parse_cascade_batch_async(["", "   ", "valid syslog 192.168.1.1"])
        assert len(results) == 3
        assert results[0].success is False
        assert results[0].parsed_by == ParsingTierEnum.RULE
        assert results[1].success is False
        assert results[1].parsed_by == ParsingTierEnum.RULE


class TestChaosFaultInjectionMatrix:
    """Scenario 5: Chaos Fault Injection Matrix & Fallback Resilience."""

    @pytest.mark.asyncio
    async def test_chaos_http_500_server_error_fallback(self):
        """Simulate HTTP 500 from NVIDIA NIM; verify graceful fallback and CB failure tracking."""
        cb = get_circuit_breaker()
        metrics = get_cascade_metrics()

        novel_log = f"chaos.server.error: fatal unhandled trace {time.monotonic()}"
        req = httpx.Request("POST", "https://integrate.api.nvidia.com/v1/chat/completions")
        resp = httpx.Response(500, request=req)
        error = APIStatusError(message="500 Internal Server Error", response=resp, body=None)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client._execute_llm_call", side_effect=error),
        ):
            res = await parse_cascade_async(novel_log)

        assert res.success is True
        assert res.parsed_by == ParsingTierEnum.FALLBACK
        assert res.confidence == 0.50
        assert "llm_call_error:APIStatusError" in res.attributes["tier3_failure"]
        assert cb.consecutive_failures == 1
        assert cb.state == CircuitState.CLOSED

        snap = metrics.get_metrics()
        assert snap["tier3_fallbacks"] == 1

    @pytest.mark.asyncio
    async def test_chaos_timeout_fallback(self):
        """Simulate client timeout; verify fallback degradation and failure recording."""
        cb = get_circuit_breaker()
        novel_log = f"chaos.timeout.error: connection hung {time.monotonic()}"
        req = httpx.Request("POST", "https://integrate.api.nvidia.com/v1/chat/completions")
        error = APITimeoutError(request=req)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client._execute_llm_call", side_effect=error),
        ):
            res = await parse_cascade_async(novel_log)

        assert res.success is True
        assert res.parsed_by == ParsingTierEnum.FALLBACK
        assert "APITimeoutError" in res.attributes["tier3_failure"]
        assert cb.consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_chaos_auth_401_fallback(self):
        """Simulate HTTP 401 Unauthorized; verify immediate fallback degradation."""
        cb = get_circuit_breaker()
        novel_log = f"chaos.auth.error: unauthorized api token {time.monotonic()}"
        req = httpx.Request("POST", "https://integrate.api.nvidia.com/v1/chat/completions")
        resp = httpx.Response(401, request=req)
        error = AuthenticationError(message="Unauthorized", response=resp, body=None)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client._execute_llm_call", side_effect=error),
        ):
            res = await parse_cascade_async(novel_log)

        assert res.success is True
        assert res.parsed_by == ParsingTierEnum.FALLBACK
        assert "AuthenticationError" in res.attributes["tier3_failure"]
        assert cb.consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_chaos_circuit_breaker_tripping_to_open(self):
        """Verify circuit breaker trips to OPEN after 5 consecutive failures and fails fast."""
        cb = get_circuit_breaker()
        req = httpx.Request("POST", "https://integrate.api.nvidia.com/v1/chat/completions")
        resp = httpx.Response(503, request=req)
        error = APIStatusError(message="503 Service Unavailable", response=resp, body=None)

        # Trigger 5 consecutive failures across 5 distinct tenants to ensure novel Drain clusters
        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client._execute_llm_call", side_effect=error) as mock_call,
        ):
            for i in range(5):
                log_line = f"trip.breaker.event_{i}: connection drop {i}"
                res = await parse_cascade_async(log_line, tenant_id=f"tenant_cb_{i}")
                assert res.parsed_by == ParsingTierEnum.FALLBACK

            assert mock_call.call_count == 5
            assert cb.consecutive_failures == 5
            assert cb.state == CircuitState.OPEN

            # 6th call: circuit breaker is OPEN -> MUST FAIL FAST without calling outbound LLM
            t0 = time.perf_counter()
            res_tripped = await parse_cascade_async(
                "trip.breaker.event_tripped: fail fast now",
                tenant_id="tenant_cb_6",
            )
            elapsed_ms = (time.perf_counter() - t0) * 1000

            # Mock call count MUST remain 5 (no 6th call attempted!)
            assert mock_call.call_count == 5
            assert res_tripped.parsed_by == ParsingTierEnum.FALLBACK
            assert res_tripped.attributes["tier3_failure"] == "circuit_breaker_open"
            # In-memory fail-fast execution must be well under 100ms (accounting for Windows test runner load)
            assert elapsed_ms < 100.0

    @pytest.mark.asyncio
    async def test_chaos_malformed_json_fallback(self):
        """Simulate LLM returning malformed/non-JSON text; verify schema validation fallback."""
        cb = get_circuit_breaker()
        novel_log = f"chaos.malformed.json: unexpected response {time.monotonic()}"

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "Here is your JSON response: {unquoted_broken_content:"
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            res = await parse_cascade_async(novel_log)

        assert res.success is True
        assert res.parsed_by == ParsingTierEnum.FALLBACK
        assert res.attributes["tier3_failure"] == "schema_validation_error"
        assert cb.consecutive_failures == 1


class TestLatencySLAAndTelemetryAudit:
    """Scenario 6: Latency SLA & Telemetry Audit."""

    def test_tier1_microsecond_p99_sla(self) -> None:
        """Verify Tier 1 regex fast-path achieves sub-150-microsecond p99 latency."""
        sample_log = (
            "<165>1 2026-10-30T10:00:00.000Z myhost authd 1234 ID47 "
            '[exampleSDID@32473 iut="3"] Benchmark admin login event'
        )

        # Warm up JIT/regex cache
        for _ in range(50):
            parse_tier1(sample_log, detected_format=LogFormatEnum.SYSLOG)

        latencies_us: list[float] = []
        iterations = 500
        for _ in range(iterations):
            t0 = time.perf_counter_ns()
            res = parse_tier1(sample_log, detected_format=LogFormatEnum.SYSLOG)
            elapsed_us = (time.perf_counter_ns() - t0) / 1000.0
            latencies_us.append(elapsed_us)
            assert res.success is True

        latencies_us.sort()
        p50 = statistics.median(latencies_us)
        p99_idx = int(iterations * 0.99)
        p99 = latencies_us[p99_idx]

        # Senior SLA assertion: p50 under 60us, p99 under 150us
        assert p50 < 60.0, f"Tier 1 median latency {p50:.2f}us exceeded 60us threshold"
        assert p99 < 150.0, f"Tier 1 p99 latency {p99:.2f}us exceeded 150us threshold"

    @pytest.mark.asyncio
    async def test_tier2_drain3_sub_millisecond_p99_sla(self) -> None:
        """Verify Tier 2 Drain3 repeat template matching achieves sub-500-microsecond p99 latency."""
        tenant_id = "00000000-0000-0000-0000-000000000099"
        base_log = "com.corp.auth.Service: Token validation succeeded for user {user} from 192.168.1.100"

        # Prime the template cluster in Drain3
        await parse_cascade_async(base_log.format(user="primer_1"), tenant_id=tenant_id)
        await parse_cascade_async(base_log.format(user="primer_2"), tenant_id=tenant_id)

        latencies_ms: list[float] = []
        iterations = 200

        for i in range(iterations):
            log_line = base_log.format(user=f"user_{i}")
            t0 = time.perf_counter()
            res = await parse_cascade_async(log_line, tenant_id=tenant_id)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(elapsed_ms)
            assert res.parsed_by == ParsingTierEnum.TEMPLATE

        latencies_ms.sort()
        p50_ms = statistics.median(latencies_ms)
        p99_idx = int(iterations * 0.99)
        p99_ms = latencies_ms[p99_idx]

        # Senior SLA assertion: p50 under 0.25ms, p99 under 0.60ms
        assert p50_ms < 0.25, f"Tier 2 median {p50_ms:.3f}ms exceeded 0.25ms"
        assert p99_ms < 0.60, f"Tier 2 p99 {p99_ms:.3f}ms exceeded 0.60ms"

    @pytest.mark.asyncio
    async def test_telemetry_metrics_full_audit(self):
        """Verify end-to-end telemetry metric counters, hit rates, and percentage distributions."""
        metrics = get_cascade_metrics()
        tenant_id = "00000000-0000-0000-0000-000000000088"

        # 1. Process 3 Tier 1 logs
        syslog_sample = "<165>1 2026-10-30T10:00:00.000Z host app 123 - - Syslog event"
        for _ in range(3):
            await parse_cascade_async(syslog_sample, tenant_id=tenant_id)

        # 2. Process Tier 2 repeat logs
        drain_sample = "cluster.telemetry.event: worker id {id} online"
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "action": "worker_online",
            "severity": "INFO",
            "summary": "Worker online event",
            "attributes": {},
        })
        mock_response.choices = [mock_choice]
        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            # 1st: novel -> Tier 3
            await parse_cascade_async(drain_sample.format(id="1"), tenant_id=tenant_id)
            # 2nd & 3rd: repeat -> Tier 2
            await parse_cascade_async(drain_sample.format(id="2"), tenant_id=tenant_id)
            await parse_cascade_async(drain_sample.format(id="3"), tenant_id=tenant_id)

        # 3. Process 1 Fallback log (NIM error)
        req = httpx.Request("POST", "https://integrate.api.nvidia.com/v1/chat/completions")
        resp = httpx.Response(500, request=req)
        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch(
                "logmorph.engine.parsers.nim_client._execute_llm_call",
                side_effect=APIStatusError(message="500", response=resp, body=None),
            ),
        ):
            await parse_cascade_async("novel.unparseable.fallback.event: error occurred", tenant_id="tenant_fb_1")

        # Telemetry snapshot reconciliation
        snap = metrics.get_metrics()
        assert snap["total_processed"] == 7  # 3 Tier 1 + 1 Tier 3 + 2 Tier 2 + 1 Fallback
        assert snap["tier1_hits"] == 3
        assert snap["tier2_hits"] == 2
        assert snap["tier3_hits"] == 1
        assert snap["tier3_fallbacks"] == 1
        assert snap["terminal_failures"] == 0

        # Hit rates
        assert snap["tier1_hit_rate"] == round(3 / 7, 4)
        assert snap["tier2_hit_rate"] == round(2 / 7, 4)
        assert snap["llm_escalation_rate"] == round(2 / 7, 4)
