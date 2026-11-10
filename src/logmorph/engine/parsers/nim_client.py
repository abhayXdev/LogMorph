"""Tier 3 NVIDIA NIM LLM Client for Novel Log Extraction & Normalization."""

import asyncio
import concurrent.futures
import enum
import json
import logging
import random
import time
from typing import Any
from uuid import UUID

import httpx
from openai import (
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    AuthenticationError,
    BadRequestError,
    PermissionDeniedError,
    RateLimitError,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from logmorph.config import settings
from logmorph.domain.uls import (
    DestinationInfo,
    ParsingTierEnum,
    SecurityContext,
    SeverityEnum,
    SourceInfo,
)
from logmorph.engine.parsers.base import ParsedResult

logger = logging.getLogger(__name__)

# Constants and Configuration Knobs
LLM_TIMEOUT_SECONDS: float = 3.0
SEMAPHORE_WAIT_TIMEOUT: float = 1.0
MAX_CONCURRENT_LLM_REQUESTS: int = 10
MAX_RAW_LOG_CHARS: int = 2000
MAX_TEMPLATE_CHARS: int = 500
MAX_RETRIES: int = 1
CIRCUIT_FAILURE_THRESHOLD: int = 5
CIRCUIT_COOLDOWN_SECONDS: float = 30.0

SYSTEM_PROMPT = (
    "You are the Tier 3 semantic parsing engine of LogMorph, a high-throughput Universal Log Normalizer.\n"
    "Your goal is to parse unstructured, novel log events into standardized security and systems telemetry.\n"
    "You MUST output valid, raw JSON adhering strictly to this schema:\n"
    "{\n"
    '  "action": "normalized_action_verb",\n'
    '  "severity": "CRITICAL|ERROR|WARNING|INFO|DEBUG",\n'
    '  "source_ip": null,\n'
    '  "source_port": null,\n'
    '  "dest_ip": null,\n'
    '  "dest_port": null,\n'
    '  "user": null,\n'
    '  "summary": "One sentence summary",\n'
    '  "attributes": {}\n'
    "}\n"
    "Never include markdown code blocks or explanations outside the JSON object. Output ONLY raw JSON."
)


class Tier3ExtractionSchema(BaseModel):
    """Pydantic validation schema for structured output from Tier 3 LLM."""

    model_config = ConfigDict(extra="ignore")

    action: str = Field(..., description="Normalized action verb (e.g. timeout, auth_failure)")
    severity: SeverityEnum = Field(..., description="Standard RFC 5424 severity level")
    source_ip: str | None = Field(default=None, description="Source IP address if present")
    source_port: int | None = Field(default=None, description="Source port number if present")
    dest_ip: str | None = Field(default=None, description="Destination IP address if present")
    dest_port: int | None = Field(default=None, description="Destination port number if present")
    user: str | None = Field(default=None, description="Associated user or identity")
    summary: str = Field(..., description="One-sentence human-readable semantic summary")
    attributes: dict[str, Any] = Field(default_factory=dict, description="Additional dynamic key-values")

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> Any:
        """Permissively map common LLM abbreviations to RFC 5424 SeverityEnum."""
        if isinstance(v, str):
            s = v.strip().upper()
            mapping = {
                "INFO": SeverityEnum.INFORMATIONAL,
                "INFORMATIONAL": SeverityEnum.INFORMATIONAL,
                "WARN": SeverityEnum.WARNING,
                "WARNING": SeverityEnum.WARNING,
                "ERR": SeverityEnum.ERROR,
                "ERROR": SeverityEnum.ERROR,
                "CRIT": SeverityEnum.CRITICAL,
                "CRITICAL": SeverityEnum.CRITICAL,
                "FATAL": SeverityEnum.EMERGENCY,
                "EMERG": SeverityEnum.EMERGENCY,
                "EMERGENCY": SeverityEnum.EMERGENCY,
                "ALERT": SeverityEnum.ALERT,
                "NOTICE": SeverityEnum.NOTICE,
                "DEBUG": SeverityEnum.DEBUG,
            }
            if s in mapping:
                return mapping[s]
        return v


class CircuitState(enum.StrEnum):
    """Circuit breaker operational states."""

    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """In-memory Circuit Breaker to prevent cascading failures to NVIDIA NIM."""

    def __init__(
        self,
        failure_threshold: int = CIRCUIT_FAILURE_THRESHOLD,
        cooldown_seconds: float = CIRCUIT_COOLDOWN_SECONDS,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.state: CircuitState = CircuitState.CLOSED
        self.consecutive_failures: int = 0
        self.last_state_change: float = 0.0
        self._lock = asyncio.Lock()

    async def can_attempt(self) -> bool:
        """Evaluate if an outbound request is permitted under circuit breaker rules."""
        async with self._lock:
            now = time.monotonic()
            if self.state == CircuitState.OPEN:
                if now - self.last_state_change >= self.cooldown_seconds:
                    logger.info("Circuit breaker cooldown expired; entering HALF_OPEN probe state")
                    self.state = CircuitState.HALF_OPEN
                    self.last_state_change = now
                    return True
                return False
            return True

    async def record_success(self) -> None:
        """Record successful logical invocation, resetting failure counts."""
        async with self._lock:
            if self.state == CircuitState.HALF_OPEN:
                logger.info("Probe request succeeded; resetting circuit breaker to CLOSED")
            self.state = CircuitState.CLOSED
            self.consecutive_failures = 0
            self.last_state_change = time.monotonic()

    async def record_failure(self) -> None:
        """Record failed logical invocation, tripping to OPEN if threshold exceeded."""
        async with self._lock:
            now = time.monotonic()
            self.consecutive_failures += 1
            if self.state == CircuitState.HALF_OPEN:
                logger.warning("Probe request failed in HALF_OPEN; reopening circuit for %ss", self.cooldown_seconds)
                self.state = CircuitState.OPEN
                self.last_state_change = now
            elif self.consecutive_failures >= self.failure_threshold:
                logger.warning(
                    "Circuit breaker tripped to OPEN after %d consecutive failures; cooling down for %ss",
                    self.consecutive_failures,
                    self.cooldown_seconds,
                )
                self.state = CircuitState.OPEN
                self.last_state_change = now

    async def reset(self) -> None:
        """Manually reset the circuit breaker (primarily for test isolation)."""
        async with self._lock:
            self.state = CircuitState.CLOSED
            self.consecutive_failures = 0
            self.last_state_change = 0.0


# Module-level singletons
_client: AsyncOpenAI | None = None
_client_lock = asyncio.Lock()
_circuit_breaker = CircuitBreaker()
_semaphore = asyncio.Semaphore(MAX_CONCURRENT_LLM_REQUESTS)


def get_circuit_breaker() -> CircuitBreaker:
    """Access the global circuit breaker instance."""
    return _circuit_breaker


def get_semaphore() -> asyncio.Semaphore:
    """Access the global concurrency semaphore."""
    return _semaphore


async def get_nim_client() -> AsyncOpenAI:
    """Retrieve or lazily initialize the singleton AsyncOpenAI client."""
    global _client
    if _client is None:
        async with _client_lock:
            if _client is None:
                api_key = settings.NVIDIA_NIM_API_KEY or "nvapi-dummy"
                base_url = settings.NVIDIA_NIM_BASE_URL
                _client = AsyncOpenAI(
                    api_key=api_key,
                    base_url=base_url,
                    timeout=LLM_TIMEOUT_SECONDS,
                )
    return _client


async def close_nim_client() -> None:
    """Gracefully close and dispose the singleton AsyncOpenAI client."""
    global _client
    async with _client_lock:
        if _client is not None:
            await _client.close()
            _client = None


def _create_fallback_result(
    tier2_result: ParsedResult,
    reason: str,
) -> ParsedResult:
    """Construct a graceful Tier 2 fallback ParsedResult tagged with failure metadata."""
    attributes = dict(tier2_result.attributes)
    attributes["tier3_failure"] = reason
    return ParsedResult(
        success=tier2_result.success,
        format=tier2_result.format,
        parsed_by=ParsingTierEnum.FALLBACK,
        confidence=tier2_result.confidence,
        action=tier2_result.action,
        raw_timestamp=tier2_result.raw_timestamp,
        severity=tier2_result.severity,
        source=tier2_result.source,
        destination=tier2_result.destination,
        security=tier2_result.security,
        attributes=attributes,
        error_message=tier2_result.error_message,
    )


def _build_user_prompt(raw_log: str, tier2_result: ParsedResult) -> str:
    """Construct the contextual JSON payload for the LLM prompt."""
    mined_template = str(tier2_result.attributes.get("template", ""))
    masked_params = tier2_result.attributes.get("masked_parameters", {})

    payload = {
        "raw_log": raw_log[:MAX_RAW_LOG_CHARS],
        "mined_template": mined_template[:MAX_TEMPLATE_CHARS],
        "candidate_entities": masked_params,
        "heuristic_severity": tier2_result.severity.value,
    }
    return json.dumps(payload, separators=(",", ":"))


def _clean_json_content(content: str) -> str:
    """Strip possible markdown code block fences wrapping JSON output."""
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    return stripped


async def _execute_llm_call(
    client: AsyncOpenAI,
    model: str,
    user_prompt: str,
) -> tuple[str, float]:
    """Execute chat completion with retry policy and per-attempt timeout."""
    attempts = 0
    max_attempts = 1 + MAX_RETRIES

    while attempts < max_attempts:
        attempts += 1
        t0 = time.perf_counter()
        try:
            try:
                # Attempt with response_format={"type": "json_object"}
                resp = await client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    response_format={"type": "json_object"},
                    max_tokens=512,
                    temperature=0.0,
                )
            except BadRequestError as format_err:
                if "response_format" in str(format_err).lower() or "json_object" in str(format_err).lower():
                    logger.debug("json_object response_format unsupported (%s); falling back to direct prompt", format_err)
                    resp = await client.chat.completions.create(
                        model=model,
                        messages=[
                            {"role": "system", "content": SYSTEM_PROMPT},
                            {"role": "user", "content": user_prompt},
                        ],
                        max_tokens=512,
                        temperature=0.0,
                    )
                else:
                    raise format_err

            elapsed_ms = (time.perf_counter() - t0) * 1000
            content = resp.choices[0].message.content
            if content is None:
                raise ValueError("Model returned empty message content (possible thinking token redirection)")
            return content, elapsed_ms

        except (AuthenticationError, BadRequestError, PermissionDeniedError) as non_retryable:
            logger.error("Non-retryable API error during Tier 3 LLM call: %s", non_retryable)
            raise non_retryable

        except (APITimeoutError, httpx.TimeoutException, RateLimitError, APIStatusError) as retryable:
            is_server_or_rate = (
                isinstance(retryable, APIStatusError) and retryable.status_code in {429, 500, 502, 503, 504}
            ) or isinstance(retryable, (APITimeoutError, httpx.TimeoutException, RateLimitError))

            if is_server_or_rate and attempts < max_attempts:
                backoff = 0.5 * (1.0 + random.uniform(0.0, 0.5))
                logger.warning(
                    "Retryable error on attempt %d/%d (%s). Backing off for %.2fs",
                    attempts,
                    max_attempts,
                    retryable,
                    backoff,
                )
                await asyncio.sleep(backoff)
                continue
            logger.error("LLM call failed after attempt %d/%d: %s", attempts, max_attempts, retryable)
            raise retryable

        except Exception as unhandled:
            if attempts < max_attempts:
                backoff = 0.5 * (1.0 + random.uniform(0.0, 0.5))
                logger.warning("Transient error on attempt %d: %s. Retrying after %.2fs", attempts, unhandled, backoff)
                await asyncio.sleep(backoff)
                continue
            raise unhandled

    raise RuntimeError("Exhausted LLM call attempts")


async def parse_tier3_async(
    raw_log: str,
    tier2_result: ParsedResult,
    tenant_id: str | UUID | None = None,
) -> ParsedResult:
    """Asynchronously parse and enrich a novel log using NVIDIA NIM LLM.

    Args:
        raw_log: The raw unparsed log string.
        tier2_result: The intermediate ParsedResult generated by Tier 2 Drain3.
        tenant_id: Multi-tenant isolation identifier.

    Returns:
        ParsedResult with parsed_by=ParsingTierEnum.LLM (or FALLBACK on degradation).
    """
    # 0. API Key check - offline/dev bypass without network calls
    if not settings.NVIDIA_NIM_API_KEY:
        logger.debug("NVIDIA_NIM_API_KEY not configured; bypassing Tier 3 to Tier 2 fallback")
        return _create_fallback_result(tier2_result, reason="missing_api_key")

    # 1. Circuit Breaker Check (cheap, in-memory, no I/O)
    if not await _circuit_breaker.can_attempt():
        logger.debug("Circuit breaker is OPEN; bypassing Tier 3 to Tier 2 fallback")
        return _create_fallback_result(tier2_result, reason="circuit_breaker_open")

    # 2. Semaphore Concurrency Slot Acquisition (bounded wait)
    try:
        await asyncio.wait_for(_semaphore.acquire(), timeout=SEMAPHORE_WAIT_TIMEOUT)
    except TimeoutError:
        logger.warning(
            "Timed out waiting %.2fs for Tier 3 concurrency slot; degrading to Tier 2 fallback",
            SEMAPHORE_WAIT_TIMEOUT,
        )
        return _create_fallback_result(tier2_result, reason="concurrency_timeout")

    try:
        client = await get_nim_client()
        user_prompt = _build_user_prompt(raw_log, tier2_result)
        model = settings.LLM_MODEL

        try:
            content, elapsed_ms = await _execute_llm_call(client, model, user_prompt)
        except Exception as call_err:
            await _circuit_breaker.record_failure()
            return _create_fallback_result(tier2_result, reason=f"llm_call_error:{type(call_err).__name__}")

        # 3. JSON Parsing & Schema Validation
        try:
            clean_json = _clean_json_content(content)
            data = json.loads(clean_json)
            schema = Tier3ExtractionSchema.model_validate(data)
        except (json.JSONDecodeError, ValidationError) as val_err:
            logger.warning("Tier 3 LLM schema validation error: %s", val_err)
            # Invalid output from model still counts as a logical failure for the circuit breaker
            await _circuit_breaker.record_failure()
            return _create_fallback_result(tier2_result, reason="schema_validation_error")

        # Logical success
        await _circuit_breaker.record_success()

        # 4. Construct Normalized ParsedResult
        # Source telemetry normalization: use LLM if provided, otherwise preserve Tier 2
        source = tier2_result.source
        if schema.source_ip or schema.source_port is not None:
            source = SourceInfo(
                ip=schema.source_ip or (source.ip if source else None),
                port=schema.source_port if schema.source_port is not None else (source.port if source else None),
            )

        # Destination telemetry normalization: use LLM if provided, otherwise preserve Tier 2
        dest = tier2_result.destination
        if schema.dest_ip or schema.dest_port is not None:
            dest = DestinationInfo(
                ip=schema.dest_ip or (dest.ip if dest else None),
                port=schema.dest_port if schema.dest_port is not None else (dest.port if dest else None),
            )

        # Security context normalization
        security = tier2_result.security
        if schema.user:
            security = SecurityContext(
                user=schema.user,
                process_name=security.process_name if security else None,
                process_id=security.process_id if security else None,
            )

        # Merge attributes
        merged_attributes = dict(tier2_result.attributes)
        merged_attributes.update(schema.attributes)
        merged_attributes["tier3_model"] = model
        merged_attributes["tier3_latency_ms"] = round(elapsed_ms, 2)
        merged_attributes["tier3_summary"] = schema.summary

        return ParsedResult(
            success=True,
            format=tier2_result.format,
            parsed_by=ParsingTierEnum.LLM,
            confidence=0.85,
            action=schema.action,
            raw_timestamp=tier2_result.raw_timestamp,
            severity=schema.severity,
            source=source,
            destination=dest,
            security=security,
            attributes=merged_attributes,
            error_message=None,
        )

    finally:
        _semaphore.release()


def parse_tier3(
    raw_log: str,
    tier2_result: ParsedResult,
    tenant_id: str | UUID | None = None,
) -> ParsedResult:
    """Synchronous entry point for Tier 3 LLM parsing."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(
                lambda: asyncio.run(parse_tier3_async(raw_log, tier2_result, tenant_id=tenant_id))
            ).result()
    else:
        return asyncio.run(parse_tier3_async(raw_log, tier2_result, tenant_id=tenant_id))
