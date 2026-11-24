"""Unit test suite for Tier 3 NVIDIA NIM LLM Client."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from openai import (
    APITimeoutError,
    AuthenticationError,
)
from pydantic import ValidationError

from logmorph.config import settings
from logmorph.domain.uls import (
    LogFormatEnum,
    ParsingTierEnum,
    SeverityEnum,
    SourceInfo,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.engine.parsers.nim_client import (
    CircuitBreaker,
    CircuitState,
    Tier3ExtractionSchema,
    _clean_json_content,
    close_nim_client,
    get_circuit_breaker,
    get_semaphore,
    parse_tier3,
    parse_tier3_async,
)


@pytest.fixture(autouse=True)
async def reset_nim_state():
    """Reset global circuit breaker, client, and semaphore between tests."""
    cb = get_circuit_breaker()
    await cb.reset()
    await close_nim_client()
    yield
    await cb.reset()
    await close_nim_client()


@pytest.fixture
def sample_tier2_result() -> ParsedResult:
    """Fixture providing a realistic novel Tier 2 intermediate result."""
    return ParsedResult(
        success=True,
        format=LogFormatEnum.UNSTRUCTURED,
        parsed_by=ParsingTierEnum.TEMPLATE,
        confidence=0.50,
        action="template_mined",
        raw_timestamp=None,
        severity=SeverityEnum.ERROR,
        source=SourceInfo(ip="10.0.0.1", port=8080),
        destination=None,
        security=None,
        attributes={
            "template": "ResourceAccessException: I/O error on GET request for <*>: Connect timed out",
            "cluster_id": 42,
            "cluster_size": 1,
            "masked_parameters": {"PORT": "8080"},
        },
    )


class TestTier3SchemaValidation:
    """Tests for Tier3ExtractionSchema Pydantic validation."""

    def test_valid_full_schema(self):
        data = {
            "action": "connection_timeout",
            "severity": "ERROR",
            "source_ip": "10.0.0.1",
            "source_port": 8080,
            "dest_ip": "10.0.0.2",
            "dest_port": 443,
            "user": "service_account",
            "summary": "Outbound HTTP request failed due to connection timeout.",
            "attributes": {"http_method": "GET", "target": "auth-service"},
        }
        obj = Tier3ExtractionSchema.model_validate(data)
        assert obj.action == "connection_timeout"
        assert obj.severity == SeverityEnum.ERROR
        assert obj.source_ip == "10.0.0.1"
        assert obj.source_port == 8080
        assert obj.dest_ip == "10.0.0.2"
        assert obj.dest_port == 443
        assert obj.user == "service_account"
        assert "http_method" in obj.attributes

    def test_valid_minimal_schema(self):
        data = {
            "action": "disk_full",
            "severity": "CRITICAL",
            "summary": "Storage partition /var/log is at 100% capacity.",
        }
        obj = Tier3ExtractionSchema.model_validate(data)
        assert obj.action == "disk_full"
        assert obj.severity == SeverityEnum.CRITICAL
        assert obj.source_ip is None
        assert obj.attributes == {}

    def test_invalid_missing_required_fields(self):
        with pytest.raises(ValidationError):
            Tier3ExtractionSchema.model_validate({"action": "foo"})

    def test_invalid_severity_enum(self):
        with pytest.raises(ValidationError):
            Tier3ExtractionSchema.model_validate({
                "action": "error",
                "severity": "NON_EXISTENT_SEVERITY",
                "summary": "Error occurred",
            })


class TestJsonCleaning:
    """Tests for markdown stripping helper."""

    def test_clean_raw_json(self):
        raw = '{"action": "test"}'
        assert _clean_json_content(raw) == raw

    def test_clean_markdown_fence(self):
        raw = '```json\n{"action": "test"}\n```'
        assert _clean_json_content(raw) == '{"action": "test"}'

    def test_clean_fence_without_language(self):
        raw = '```\n{"action": "test"}\n```'
        assert _clean_json_content(raw) == '{"action": "test"}'


class TestCircuitBreaker:
    """Tests for in-memory CircuitBreaker state transitions."""

    @pytest.mark.asyncio
    async def test_initial_state_closed(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=1.0)
        assert await cb.can_attempt() is True
        assert cb.state == CircuitState.CLOSED
        assert cb.consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_trips_to_open_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=1.0)
        await cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        assert cb.consecutive_failures == 1

        await cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        assert cb.consecutive_failures == 2

        await cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.consecutive_failures == 3
        assert await cb.can_attempt() is False

    @pytest.mark.asyncio
    async def test_recovers_after_cooldown_and_success(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.1)
        await cb.record_failure()
        await cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert await cb.can_attempt() is False

        # Wait for cooldown to expire
        await asyncio.sleep(0.12)
        # Should now permit a probe attempt in HALF_OPEN
        assert await cb.can_attempt() is True
        assert cb.state == CircuitState.HALF_OPEN

        # Successful probe resets to CLOSED
        await cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb.consecutive_failures == 0
        assert await cb.can_attempt() is True

    @pytest.mark.asyncio
    async def test_probe_failure_reopens_circuit(self):
        cb = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.1)
        await cb.record_failure()
        await cb.record_failure()
        assert cb.state == CircuitState.OPEN

        await asyncio.sleep(0.12)
        assert await cb.can_attempt() is True
        assert cb.state == CircuitState.HALF_OPEN

        # Probe fails
        await cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert await cb.can_attempt() is False


class TestTier3OfflineAndFallback:
    """Tests for local offline bypass and fallback mechanics."""

    @pytest.mark.asyncio
    async def test_missing_api_key_bypasses_offline(self, sample_tier2_result: ParsedResult):
        with patch.object(settings, "NVIDIA_NIM_API_KEY", None):
            res = await parse_tier3_async("some unparsed log line", sample_tier2_result)
            assert res.parsed_by == ParsingTierEnum.FALLBACK
            assert res.confidence == 0.50
            assert res.attributes.get("tier3_failure") == "missing_api_key"
            assert res.attributes.get("template") == sample_tier2_result.attributes["template"]

    @pytest.mark.asyncio
    async def test_circuit_open_bypasses_to_fallback(self, sample_tier2_result: ParsedResult):
        cb = get_circuit_breaker()
        # Force circuit OPEN
        for _ in range(5):
            await cb.record_failure()
        assert cb.state == CircuitState.OPEN

        with patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"):
            res = await parse_tier3_async("log line", sample_tier2_result)
            assert res.parsed_by == ParsingTierEnum.FALLBACK
            assert res.attributes.get("tier3_failure") == "circuit_breaker_open"

    @pytest.mark.asyncio
    async def test_concurrency_timeout_degrades_to_fallback(self, sample_tier2_result: ParsedResult):
        sem = get_semaphore()
        # Drain all slots
        slots = []
        for _ in range(10):
            slots.append(await sem.acquire())

        try:
            with (
                patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
                patch("logmorph.engine.parsers.nim_client.SEMAPHORE_WAIT_TIMEOUT", 0.05),
            ):
                t0 = time.perf_counter()
                res = await parse_tier3_async("log line", sample_tier2_result)
                elapsed = time.perf_counter() - t0
                assert elapsed < 0.2
                assert res.parsed_by == ParsingTierEnum.FALLBACK
                assert res.attributes.get("tier3_failure") == "concurrency_timeout"
        finally:
            for _ in slots:
                sem.release()


class TestTier3MockedInvocations:
    """Tests with mocked AsyncOpenAI client."""

    @pytest.mark.asyncio
    async def test_successful_extraction(self, sample_tier2_result: ParsedResult):
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "action": "connection_timeout",
            "severity": "ERROR",
            "dest_ip": "auth-service",
            "dest_port": 8080,
            "user": None,
            "summary": "HTTP connection timed out connecting to auth-service:8080",
            "attributes": {"service": "auth-service", "endpoint": "/validate"},
        })
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            res = await parse_tier3_async("raw log string", sample_tier2_result)

            assert res.success is True
            assert res.parsed_by == ParsingTierEnum.LLM
            assert res.confidence == 0.85
            assert res.action == "connection_timeout"
            assert res.severity == SeverityEnum.ERROR
            # destination should be populated from LLM output
            assert res.destination is not None
            assert res.destination.ip == "auth-service"
            assert res.destination.port == 8080
            # source should fall back to tier 2's source (10.0.0.1:8080)
            assert res.source is not None
            assert res.source.ip == "10.0.0.1"
            assert res.source.port == 8080
            # attributes should contain merged data
            assert res.attributes["service"] == "auth-service"
            assert res.attributes["template"] == sample_tier2_result.attributes["template"]
            assert res.attributes["tier3_summary"] == "HTTP connection timed out connecting to auth-service:8080"
            assert "tier3_latency_ms" in res.attributes

    @pytest.mark.asyncio
    async def test_fenced_json_extraction(self, sample_tier2_result: ParsedResult):
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "```json\n" + json.dumps({
            "action": "auth_failure",
            "severity": "WARNING",
            "source_ip": "192.168.1.100",
            "source_port": 54321,
            "user": "root",
            "summary": "Invalid login attempt for root user",
            "attributes": {},
        }) + "\n```"
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            res = await parse_tier3_async("ssh login failed", sample_tier2_result)

            assert res.parsed_by == ParsingTierEnum.LLM
            assert res.action == "auth_failure"
            assert res.severity == SeverityEnum.WARNING
            assert res.source is not None
            assert res.source.ip == "192.168.1.100"
            assert res.source.port == 54321
            assert res.security is not None
            assert res.security.user == "root"

    @pytest.mark.asyncio
    async def test_schema_validation_failure_degrades_and_records_failure(self, sample_tier2_result: ParsedResult):
        cb = get_circuit_breaker()
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = "This is not JSON text at all!"
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            res = await parse_tier3_async("bad log", sample_tier2_result)
            assert res.parsed_by == ParsingTierEnum.FALLBACK
            assert res.attributes.get("tier3_failure") == "schema_validation_error"
            assert cb.consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_retry_on_timeout_succeeds_on_second_attempt(self, sample_tier2_result: ParsedResult):
        mock_response = MagicMock()
        mock_choice = MagicMock()
        mock_choice.message.content = json.dumps({
            "action": "recovered_call",
            "severity": "INFO",
            "summary": "Succeeded on retry attempt.",
        })
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        # First call raises APITimeoutError, second succeeds
        timeout_err = APITimeoutError(request=MagicMock())
        mock_client.chat.completions.create = AsyncMock(side_effect=[timeout_err, mock_response])

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
            patch("asyncio.sleep", new_callable=AsyncMock),
        ):
            res = await parse_tier3_async("log line", sample_tier2_result)
            assert res.parsed_by == ParsingTierEnum.LLM
            assert res.action == "recovered_call"
            assert mock_client.chat.completions.create.call_count == 2

    @pytest.mark.asyncio
    async def test_non_retryable_auth_error_aborts_immediately(self, sample_tier2_result: ParsedResult):
        cb = get_circuit_breaker()
        mock_client = AsyncMock()
        auth_err = AuthenticationError("Invalid API key", response=MagicMock(status_code=401), body={})
        mock_client.chat.completions.create = AsyncMock(side_effect=auth_err)

        with (
            patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
            patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
        ):
            res = await parse_tier3_async("log line", sample_tier2_result)
            assert res.parsed_by == ParsingTierEnum.FALLBACK
            assert "llm_call_error" in res.attributes.get("tier3_failure", "")
            # Should not have retried
            assert mock_client.chat.completions.create.call_count == 1
            assert cb.consecutive_failures == 1


class TestTier3SyncWrapper:
    """Tests for synchronous parse_tier3 wrapper."""

    def test_sync_parse_tier3(self, sample_tier2_result: ParsedResult):
        with patch.object(settings, "NVIDIA_NIM_API_KEY", None):
            res = parse_tier3("sync raw log", sample_tier2_result)
            assert res.parsed_by == ParsingTierEnum.FALLBACK
            assert res.attributes.get("tier3_failure") == "missing_api_key"


class TestTier3LiveIntegration:
    """Live integration test against NVIDIA NIM using configured testing key."""

    @pytest.mark.skipif(
        not settings.NVIDIA_NIM_API_KEY or "nvapi" not in settings.NVIDIA_NIM_API_KEY,
        reason="Valid NVIDIA_NIM_API_KEY not configured",
    )
    @pytest.mark.asyncio
    async def test_live_nim_chat_completion(self, sample_tier2_result: ParsedResult):
        raw_log = (
            'org.springframework.web.client.ResourceAccessException: I/O error on GET request '
            'for "http://auth-service:8080/validate": Connect timed out'
        )
        res = await parse_tier3_async(raw_log, sample_tier2_result)

        assert res.success is True
        assert res.parsed_by == ParsingTierEnum.LLM
        assert res.confidence == 0.85
        assert res.severity in {SeverityEnum.ERROR, SeverityEnum.CRITICAL}
        assert res.destination is not None
        assert "auth-service" in (res.destination.ip or "")
        assert res.destination.port == 8080
        assert res.attributes.get("tier3_model") == settings.LLM_MODEL
        assert "tier3_latency_ms" in res.attributes
        assert len(res.attributes.get("tier3_summary", "")) > 5
