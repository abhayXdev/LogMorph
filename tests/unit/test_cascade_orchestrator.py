"""Unit test suite for the 3-Tier Adaptive Parsing Cascade Orchestrator."""

import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from logmorph.config import settings
from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum, SeverityEnum
from logmorph.engine.parsers.base import ParsedResult
from logmorph.engine.parsers.nim_client import (
    close_nim_client,
    get_circuit_breaker,
)
from logmorph.engine.parsers.orchestrator import (
    get_cascade_metrics,
    parse_cascade,
    parse_cascade_async,
    parse_cascade_batch,
    parse_cascade_batch_async,
)


@pytest.fixture(autouse=True)
async def reset_orchestrator_state():
    """Reset cascade metrics, circuit breaker, and LLM client before/after each test."""
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


class TestCascadeFastPath:
    """Tests verifying microsecond Tier 1 fast-path routing."""

    @pytest.mark.asyncio
    async def test_empty_and_whitespace_logs_short_circuit(self):
        for raw in ["", "   ", "\t\n  "]:
            res = await parse_cascade_async(raw)
            assert res.success is False
            assert res.format == LogFormatEnum.UNSTRUCTURED
            assert res.parsed_by == ParsingTierEnum.RULE
            assert res.confidence == 0.10
            assert res.attributes["cascade_route"] == ["GATE_0_EMPTY"]

    @pytest.mark.asyncio
    async def test_syslog_rfc5424_fast_path(self):
        log = (
            "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - "
            "ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] An event"
        )
        res = await parse_cascade_async(log)
        assert res.success is True
        assert res.format == LogFormatEnum.SYSLOG
        assert res.parsed_by == ParsingTierEnum.RULE
        assert res.confidence == 1.0
        assert res.attributes["cascade_route"] == ["TIER_1"]
        assert "tier1_ms" in res.attributes["tier_latencies_ms"]
        assert "tier2_ms" not in res.attributes["tier_latencies_ms"]

    @pytest.mark.asyncio
    async def test_json_fast_path(self):
        log = json.dumps({"timestamp": "2026-10-30T10:00:00Z", "level": "ERROR", "message": "Disk failure"})
        res = await parse_cascade_async(log)
        assert res.success is True
        assert res.format == LogFormatEnum.JSON
        assert res.parsed_by == ParsingTierEnum.RULE
        assert res.confidence == 1.0
        assert res.attributes["cascade_route"] == ["TIER_1"]

    @pytest.mark.asyncio
    async def test_apache_clf_fast_path(self):
        log = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
        res = await parse_cascade_async(log)
        assert res.success is True
        assert res.format == LogFormatEnum.CLF
        assert res.parsed_by == ParsingTierEnum.RULE
        assert res.confidence == 1.0
        assert res.attributes["cascade_route"] == ["TIER_1"]

    @pytest.mark.asyncio
    async def test_cef_fast_path(self):
        log = "CEF:0|Security|ThreatManager|1.0|100|Worm detected|10|src=10.0.0.1 dst=10.0.0.2"
        res = await parse_cascade_async(log)
        assert res.success is True
        assert res.format == LogFormatEnum.CEF
        assert res.parsed_by == ParsingTierEnum.RULE
        assert res.confidence == 1.0
        assert res.attributes["cascade_route"] == ["TIER_1"]

    @pytest.mark.asyncio
    async def test_leef_fast_path(self):
        log = "LEEF:2.0|Vendor|Product|Version|EventID|src=10.0.0.1\tdst=10.0.0.2"
        res = await parse_cascade_async(log)
        assert res.success is True
        assert res.format == LogFormatEnum.LEEF
        assert res.parsed_by == ParsingTierEnum.RULE
        assert res.confidence == 1.0
        assert res.attributes["cascade_route"] == ["TIER_1"]

    @pytest.mark.asyncio
    async def test_xml_fast_path(self):
        log = '<?xml version="1.0"?><Event><System><TimeCreated SystemTime="2026-10-30T10:00:00Z"/></System></Event>'
        res = await parse_cascade_async(log)
        assert res.success is True
        assert res.format == LogFormatEnum.XML
        assert res.parsed_by == ParsingTierEnum.RULE
        assert res.confidence == 1.0
        assert res.attributes["cascade_route"] == ["TIER_1"]


class TestCascadeTier2Clustering:
    """Tests verifying Tier 2 Drain3 clustering and repeat match terminal exit."""

    @pytest.mark.asyncio
    async def test_converged_unstructured_template_terminates_at_tier2(self):
        tenant_id = str(uuid.uuid4())
        raw_log = "HikariPool-1 - Connection is not available, request timed out after 30005ms"

        # Prime the miner with first occurrence (which creates cluster)
        with patch.object(settings, "NVIDIA_NIM_API_KEY", None):
            res1 = await parse_cascade_async(raw_log, tenant_id=tenant_id)
            # Novel cluster created -> routes to Tier 3, but missing API key yields FALLBACK
            assert res1.parsed_by == ParsingTierEnum.FALLBACK
            assert "TIER_2" in res1.attributes["cascade_route"]
            assert "TIER_3" in res1.attributes["cascade_route"]

            # Second occurrence of identical log -> cluster_size becomes >= 2 (converged, confidence=0.90)
            res2 = await parse_cascade_async(raw_log, tenant_id=tenant_id)
            assert res2.success is True
            assert res2.parsed_by == ParsingTierEnum.TEMPLATE
            assert res2.confidence == 0.90
            # Must terminate at Tier 2 and NOT call Tier 3
            assert res2.attributes["cascade_route"] == ["TIER_1", "TIER_2"]
            assert "TIER_3" not in res2.attributes["cascade_route"]
            assert "tier2_ms" in res2.attributes["tier_latencies_ms"]
            assert "tier3_ms" not in res2.attributes["tier_latencies_ms"]

    @pytest.mark.asyncio
    async def test_syntax_garbage_terminates_at_tier2_without_llm(self):
        tenant_id = str(uuid.uuid4())
        # Mock Tier 2 returning low confidence (<0.30)
        mock_tier2 = ParsedResult(
            success=False,
            format=LogFormatEnum.UNSTRUCTURED,
            parsed_by=ParsingTierEnum.TEMPLATE,
            confidence=0.20,
            error_message="Garbage input unparseable",
        )
        with patch("logmorph.engine.parsers.orchestrator.parse_tier2_async", AsyncMock(return_value=mock_tier2)):
            res = await parse_cascade_async("@@@###$$$%%%^^^&&&", tenant_id=tenant_id)
            assert res.success is False
            assert res.parsed_by == ParsingTierEnum.TEMPLATE
            assert res.confidence == 0.20
            # Never touched Tier 3
            assert res.attributes["cascade_route"] == ["TIER_1", "TIER_2"]
            assert "TIER_3" not in res.attributes["cascade_route"]


class TestCascadeTier3Escalation:
    """Tests verifying novel unstructured log escalation to Tier 3 LLM."""

    @pytest.mark.asyncio
    async def test_novel_log_escalates_to_tier3_and_succeeds(self):
        tenant_id = str(uuid.uuid4())
        raw_log = 'org.springframework.web.client.ResourceAccessException: I/O error on GET request for "http://auth-service:8080/validate": Connect timed out'

        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "action": "connection_timeout",
            "severity": "ERROR",
            "dest_ip": "auth-service",
            "dest_port": 8080,
            "user": None,
            "summary": "HTTP connection timed out connecting to auth-service:8080",
            "attributes": {"service": "auth-service"},
        })
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            res = await parse_cascade_async(raw_log, tenant_id=tenant_id)
            assert res.success is True
            assert res.parsed_by == ParsingTierEnum.LLM
            assert res.confidence == 0.85
            assert res.action == "connection_timeout"
            assert res.severity == SeverityEnum.ERROR
            assert res.destination is not None
            assert res.destination.ip == "auth-service"
            assert res.destination.port == 8080
            assert res.attributes["cascade_route"] == ["TIER_1", "TIER_2", "TIER_3"]
            assert "tier1_ms" in res.attributes["tier_latencies_ms"]
            assert "tier2_ms" in res.attributes["tier_latencies_ms"]
            assert "tier3_ms" in res.attributes["tier_latencies_ms"]
            assert res.attributes["cascade_tier"] == "LLM"


class TestCascadeDegradationAndFallback:
    """Tests verifying graceful cascade fallback when Tier 3 degrades."""

    @pytest.mark.asyncio
    async def test_offline_environment_falls_back_gracefully(self):
        tenant_id = str(uuid.uuid4())
        raw_log = "Random custom stack trace occurred at Class.method(Class.java:123)"

        with patch.object(settings, "NVIDIA_NIM_API_KEY", None):
            res = await parse_cascade_async(raw_log, tenant_id=tenant_id)
            assert res.parsed_by == ParsingTierEnum.FALLBACK
            assert res.confidence == 0.50
            assert res.attributes["cascade_route"] == ["TIER_1", "TIER_2", "TIER_3", "FALLBACK"]
            assert res.attributes.get("tier3_failure") == "missing_api_key"
            assert "template" in res.attributes

    @pytest.mark.asyncio
    async def test_circuit_breaker_open_falls_back_immediately(self):
        tenant_id = str(uuid.uuid4())
        raw_log = "Error connecting to backend service"

        cb = get_circuit_breaker()
        for _ in range(5):
            await cb.record_failure()
        assert cb.state.value == "OPEN"

        with patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"):
            res = await parse_cascade_async(raw_log, tenant_id=tenant_id)
            assert res.parsed_by == ParsingTierEnum.FALLBACK
            assert res.attributes.get("tier3_failure") == "circuit_breaker_open"
            assert res.attributes["cascade_route"] == ["TIER_1", "TIER_2", "TIER_3", "FALLBACK"]

    @pytest.mark.asyncio
    async def test_unexpected_tier3_exception_caught_safely(self):
        tenant_id = str(uuid.uuid4())
        raw_log = "Unexpected crash in worker thread"

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch(
                "logmorph.engine.parsers.orchestrator.parse_tier3_async",
                AsyncMock(side_effect=RuntimeError("Sudden network failure")),
            ),
        ):
            res = await parse_cascade_async(raw_log, tenant_id=tenant_id)
            assert res.parsed_by == ParsingTierEnum.FALLBACK
            assert "Sudden network failure" in res.error_message
            assert res.attributes["cascade_route"] == ["TIER_1", "TIER_2", "TIER_3", "FALLBACK"]


class TestCascadeBatchProcessing:
    """Tests verifying 2-phase concurrent batch processing and index preservation."""

    @pytest.mark.asyncio
    async def test_empty_batch_returns_empty_list(self):
        res = await parse_cascade_batch_async([])
        assert res == []

    @pytest.mark.asyncio
    async def test_heterogeneous_batch_preserves_order_and_routes_accurately(self):
        tenant_id = str(uuid.uuid4())
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "action": "novel_exception",
            "severity": "ERROR",
            "summary": "Novel error processed by LLM.",
        })
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        batch = [
            # 0. Syslog (Tier 1)
            "<165>1 2003-10-11T22:14:15.003Z host app - ID47 [test] Syslog message",
            # 1. Empty line (Gate 0)
            "   ",
            # 2. JSON (Tier 1)
            json.dumps({"message": "JSON alert", "level": "WARNING"}),
            # 3. Novel unstructured (Tier 3)
            "CustomService: connection pool exhausted after 30000ms",
            # 4. Apache CLF (Tier 1)
            '10.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /test HTTP/1.1" 200 1234',
        ]

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            results = await parse_cascade_batch_async(batch, tenant_id=tenant_id)

            assert len(results) == 5

            # Index 0: Syslog
            assert results[0].success is True
            assert results[0].format == LogFormatEnum.SYSLOG
            assert results[0].parsed_by == ParsingTierEnum.RULE

            # Index 1: Empty
            assert results[1].success is False
            assert results[1].attributes["cascade_route"] == ["GATE_0_EMPTY"]

            # Index 2: JSON
            assert results[2].success is True
            assert results[2].format == LogFormatEnum.JSON
            assert results[2].parsed_by == ParsingTierEnum.RULE

            # Index 3: Novel unstructured
            assert results[3].success is True
            assert results[3].parsed_by == ParsingTierEnum.LLM
            assert results[3].action == "novel_exception"

            # Index 4: Apache CLF
            assert results[4].success is True
            assert results[4].format == LogFormatEnum.CLF
            assert results[4].parsed_by == ParsingTierEnum.RULE


class TestCascadeTelemetryAndProfiling:
    """Tests verifying execution telemetry injection and metrics tracking."""

    @pytest.mark.asyncio
    async def test_metrics_collection_and_reset(self):
        metrics = get_cascade_metrics()
        metrics.reset()

        # Run 1 Tier 1 log
        syslog = "<165>1 2003-10-11T22:14:15.003Z host app - - - Event"
        await parse_cascade_async(syslog)

        # Run 1 empty log (terminal failure)
        await parse_cascade_async("")

        snap = metrics.get_metrics()
        assert snap["total_processed"] == 2
        assert snap["tier1_hits"] == 1
        assert snap["terminal_failures"] == 1
        assert snap["tier1_hit_rate"] == 0.5
        assert snap["llm_escalation_rate"] == 0.0

        metrics.reset()
        assert metrics.total_processed == 0


class TestCascadeSyncWrapper:
    """Tests for synchronous convenience functions."""

    def test_sync_parse_cascade(self):
        syslog = "<165>1 2003-10-11T22:14:15.003Z host app - - - Event"
        res = parse_cascade(syslog)
        assert res.success is True
        assert res.parsed_by == ParsingTierEnum.RULE

    def test_sync_parse_cascade_batch(self):
        batch = [
            "<165>1 2003-10-11T22:14:15.003Z host app - - - Event",
            json.dumps({"msg": "hello", "level": "INFO"}),
        ]
        results = parse_cascade_batch(batch)
        assert len(results) == 2
        assert results[0].parsed_by == ParsingTierEnum.RULE
        assert results[1].parsed_by == ParsingTierEnum.RULE
