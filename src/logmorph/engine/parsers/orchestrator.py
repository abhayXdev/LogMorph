"""3-Tier Adaptive Parsing Cascade Orchestrator."""

import asyncio
import concurrent.futures
import dataclasses
import logging
import threading
import time
from typing import Any
from uuid import UUID

from logmorph.domain.uls import LogFormatEnum, ParsingTierEnum, SeverityEnum
from logmorph.engine.detector import detect_format
from logmorph.engine.parsers.base import ParsedResult
from logmorph.engine.parsers.drain_miner import parse_tier2_async, should_route_to_llm
from logmorph.engine.parsers.nim_client import parse_tier3_async
from logmorph.engine.parsers.tier1 import parse_tier1

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class CascadeMetrics:
    """Thread-safe telemetry accumulator tracking cascade throughput and tier hit rates."""

    total_processed: int = 0
    tier1_hits: int = 0
    tier2_hits: int = 0
    tier3_hits: int = 0
    tier3_fallbacks: int = 0
    terminal_failures: int = 0
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)

    def record_hit(self, tier: ParsingTierEnum, success: bool) -> None:
        """Increment counters based on resolving tier and terminal status."""
        with self._lock:
            self.total_processed += 1
            if tier == ParsingTierEnum.RULE:
                if success:
                    self.tier1_hits += 1
                else:
                    self.terminal_failures += 1
            elif tier == ParsingTierEnum.TEMPLATE:
                if success:
                    self.tier2_hits += 1
                else:
                    self.terminal_failures += 1
            elif tier == ParsingTierEnum.LLM:
                self.tier3_hits += 1
            elif tier == ParsingTierEnum.FALLBACK:
                self.tier3_fallbacks += 1

    def get_metrics(self) -> dict[str, Any]:
        """Return a snapshot of cascade metrics and hit rates."""
        with self._lock:
            total = self.total_processed
            return {
                "total_processed": total,
                "tier1_hits": self.tier1_hits,
                "tier2_hits": self.tier2_hits,
                "tier3_hits": self.tier3_hits,
                "tier3_fallbacks": self.tier3_fallbacks,
                "terminal_failures": self.terminal_failures,
                "tier1_hit_rate": round(self.tier1_hits / total, 4) if total > 0 else 0.0,
                "tier2_hit_rate": round(self.tier2_hits / total, 4) if total > 0 else 0.0,
                "llm_escalation_rate": (
                    round((self.tier3_hits + self.tier3_fallbacks) / total, 4) if total > 0 else 0.0
                ),
            }

    def reset(self) -> None:
        """Reset all counters (primarily for test isolation)."""
        with self._lock:
            self.total_processed = 0
            self.tier1_hits = 0
            self.tier2_hits = 0
            self.tier3_hits = 0
            self.tier3_fallbacks = 0
            self.terminal_failures = 0


# Module-level singleton metrics collector
_cascade_metrics = CascadeMetrics()


def get_cascade_metrics() -> CascadeMetrics:
    """Access the global cascade telemetry metrics instance."""
    return _cascade_metrics


def _annotate_telemetry(
    result: ParsedResult,
    route: list[str],
    tier_latencies: dict[str, float],
    total_latency_ms: float,
) -> ParsedResult:
    """Enrich ParsedResult attributes with execution telemetry and profiling data."""
    attributes = dict(result.attributes)
    attributes["cascade_tier"] = result.parsed_by.value
    attributes["cascade_total_latency_ms"] = round(total_latency_ms, 3)
    attributes["cascade_route"] = list(route)
    attributes["tier_latencies_ms"] = {k: round(v, 3) for k, v in tier_latencies.items()}
    return result.model_copy(update={"attributes": attributes})


async def parse_cascade_async(
    raw_log: str,
    detected_format: LogFormatEnum | None = None,
    tenant_id: str | UUID | None = None,
) -> ParsedResult:
    """Asynchronously route a log through the 3-Tier Adaptive Parsing Cascade.

    Flow:
    1. Input Validation: Empty/whitespace logs immediately fail (Gate 0).
    2. Tier 1 (Fast-Path Rules): If structured format and clean parse -> return immediately (~1.5μs).
    3. Tier 2 (Drain3 Clustering): If Tier 1 misses -> template clustering (~29.7μs).
       - If repeat cluster (confidence >= 0.70) -> return terminal Tier 2 result.
       - If garbage / unparseable (confidence < 0.30) -> return terminal Tier 2 failure (no LLM call).
       - If novel cluster (0.30 <= confidence < 0.70) -> escalate to Tier 3.
    4. Tier 3 (NVIDIA NIM LLM): Semantic reasoning & structured normalization (~2.0s).
       - On success -> ParsedResult(parsed_by=LLM, confidence=0.85).
       - On degradation -> ParsedResult(parsed_by=FALLBACK, confidence=0.50).

    Args:
        raw_log: Raw unparsed log string.
        detected_format: Optional pre-classified LogFormatEnum.
        tenant_id: Multi-tenant isolation identifier.

    Returns:
        Fully normalized ParsedResult annotated with execution telemetry.
    """
    start_time = time.perf_counter()
    route: list[str] = []
    tier_latencies: dict[str, float] = {}

    # Gate 0: Input Sanitization
    if not raw_log or not raw_log.strip():
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        res = ParsedResult(
            success=False,
            format=LogFormatEnum.UNSTRUCTURED,
            parsed_by=ParsingTierEnum.RULE,
            confidence=0.10,
            severity=SeverityEnum.INFORMATIONAL,
            error_message="Empty raw log line",
            attributes={
                "cascade_tier": ParsingTierEnum.RULE.value,
                "cascade_total_latency_ms": round(elapsed_ms, 3),
                "cascade_route": ["GATE_0_EMPTY"],
                "tier_latencies_ms": {},
            },
        )
        _cascade_metrics.record_hit(ParsingTierEnum.RULE, success=False)
        return res

    # Gate 1: Format Detection (if not supplied)
    if detected_format is None:
        t0_det = time.perf_counter()
        detection_res = detect_format(raw_log)
        detected_format = detection_res.detected_format
        tier_latencies["format_detection_ms"] = (time.perf_counter() - t0_det) * 1000

    # Gate 2: Tier 1 Fast-Path Dispatch
    route.append("TIER_1")
    t0_t1 = time.perf_counter()
    try:
        t1_res = parse_tier1(raw_log, detected_format=detected_format)
    except Exception as e:
        logger.warning("Unexpected exception in Tier 1 parser: %s", e)
        t1_res = ParsedResult(
            success=False,
            format=detected_format or LogFormatEnum.UNSTRUCTURED,
            parsed_by=ParsingTierEnum.RULE,
            error_message=str(e),
        )
    tier_latencies["tier1_ms"] = (time.perf_counter() - t0_t1) * 1000

    if t1_res.success and t1_res.format != LogFormatEnum.UNSTRUCTURED:
        total_elapsed_ms = (time.perf_counter() - start_time) * 1000
        annotated = _annotate_telemetry(t1_res, route, tier_latencies, total_elapsed_ms)
        _cascade_metrics.record_hit(ParsingTierEnum.RULE, success=True)
        return annotated

    # Gate 3: Tier 2 Template Mining Escalation
    route.append("TIER_2")
    t0_t2 = time.perf_counter()
    try:
        t2_res = await parse_tier2_async(raw_log, tenant_id=tenant_id)
    except Exception as e:
        logger.error("Unexpected exception in Tier 2 Drain3 miner: %s", e)
        t2_res = ParsedResult(
            success=False,
            format=LogFormatEnum.UNSTRUCTURED,
            parsed_by=ParsingTierEnum.TEMPLATE,
            confidence=0.10,
            error_message=f"Tier 2 miner exception: {e}",
        )
    tier_latencies["tier2_ms"] = (time.perf_counter() - t0_t2) * 1000

    # Check Tier 2 terminal exit conditions
    # 1. High confidence converged or generalized template (>= 0.70)
    # 2. Syntax garbage / unparseable (< 0.30 or not success)
    if not should_route_to_llm(t2_res):
        total_elapsed_ms = (time.perf_counter() - start_time) * 1000
        annotated = _annotate_telemetry(t2_res, route, tier_latencies, total_elapsed_ms)
        _cascade_metrics.record_hit(ParsingTierEnum.TEMPLATE, success=t2_res.success)
        return annotated

    # Gate 4: Tier 3 NVIDIA NIM LLM Escalation (novel cluster created)
    route.append("TIER_3")
    t0_t3 = time.perf_counter()
    try:
        t3_res = await parse_tier3_async(raw_log, t2_res, tenant_id=tenant_id)
    except Exception as e:
        logger.error("Unexpected exception invoking Tier 3 LLM client: %s", e)
        # Construct graceful fallback from t2_res
        fallback_attrs = dict(t2_res.attributes)
        fallback_attrs["tier3_failure"] = f"unhandled_orchestrator_exception:{e}"
        t3_res = ParsedResult(
            success=t2_res.success,
            format=t2_res.format,
            parsed_by=ParsingTierEnum.FALLBACK,
            confidence=t2_res.confidence,
            action=t2_res.action,
            raw_timestamp=t2_res.raw_timestamp,
            severity=t2_res.severity,
            source=t2_res.source,
            destination=t2_res.destination,
            security=t2_res.security,
            attributes=fallback_attrs,
            error_message=str(e),
        )
    tier_latencies["tier3_ms"] = (time.perf_counter() - t0_t3) * 1000

    if t3_res.parsed_by == ParsingTierEnum.FALLBACK:
        route.append("FALLBACK")

    total_elapsed_ms = (time.perf_counter() - start_time) * 1000
    annotated = _annotate_telemetry(t3_res, route, tier_latencies, total_elapsed_ms)
    _cascade_metrics.record_hit(t3_res.parsed_by, success=t3_res.success)
    return annotated


def parse_cascade(
    raw_log: str,
    detected_format: LogFormatEnum | None = None,
    tenant_id: str | UUID | None = None,
) -> ParsedResult:
    """Synchronous entry point for parse_cascade_async."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(
                lambda: asyncio.run(
                    parse_cascade_async(raw_log, detected_format=detected_format, tenant_id=tenant_id)
                )
            ).result()
    else:
        return asyncio.run(
            parse_cascade_async(raw_log, detected_format=detected_format, tenant_id=tenant_id)
        )


async def parse_cascade_batch_async(
    raw_logs: list[str],
    detected_formats: list[LogFormatEnum | None] | None = None,
    tenant_id: str | UUID | None = None,
) -> list[ParsedResult]:
    """Asynchronously process a batch of logs using 2-phase concurrency decoupling.

    Phase 1: In-memory evaluation of Tier 1 and Tier 2 across the entire batch (~30μs/item).
    Phase 2: Concurrent dispatch of novel tail logs requiring Tier 3 via asyncio.gather()
             (bounded by Tier 3's concurrency semaphore).

    Preserves 100% strict 1-to-1 input index ordering.

    Args:
        raw_logs: List of unparsed log strings.
        detected_formats: Optional parallel list of format hints.
        tenant_id: Multi-tenant isolation identifier.

    Returns:
        List of normalized ParsedResults matching input sequence.
    """
    if not raw_logs:
        return []

    count = len(raw_logs)
    results: list[ParsedResult | None] = [None] * count
    formats = detected_formats if (detected_formats and len(detected_formats) == count) else [None] * count

    # Items needing Phase 2 Tier 3 processing:
    # tuple: (index, raw_log, t2_res, route, tier_latencies, start_time)
    pending_llm: list[tuple[int, str, ParsedResult, list[str], dict[str, float], float]] = []

    # Phase 1: Microsecond Fast-Path Sweep
    for idx, (raw_log, fmt) in enumerate(zip(raw_logs, formats, strict=False)):
        start_time = time.perf_counter()
        route: list[str] = []
        tier_latencies: dict[str, float] = {}

        # Gate 0: Empty check
        if not raw_log or not raw_log.strip():
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            res = ParsedResult(
                success=False,
                format=LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.RULE,
                confidence=0.10,
                severity=SeverityEnum.INFORMATIONAL,
                error_message="Empty raw log line",
                attributes={
                    "cascade_tier": ParsingTierEnum.RULE.value,
                    "cascade_total_latency_ms": round(elapsed_ms, 3),
                    "cascade_route": ["GATE_0_EMPTY"],
                    "tier_latencies_ms": {},
                },
            )
            _cascade_metrics.record_hit(ParsingTierEnum.RULE, success=False)
            results[idx] = res
            continue

        # Format detection if needed
        if fmt is None:
            t0_det = time.perf_counter()
            detection_res = detect_format(raw_log)
            fmt = detection_res.detected_format
            tier_latencies["format_detection_ms"] = (time.perf_counter() - t0_det) * 1000

        # Tier 1 execution
        route.append("TIER_1")
        t0_t1 = time.perf_counter()
        try:
            t1_res = parse_tier1(raw_log, detected_format=fmt)
        except Exception as e:
            t1_res = ParsedResult(
                success=False,
                format=fmt or LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.RULE,
                error_message=str(e),
            )
        tier_latencies["tier1_ms"] = (time.perf_counter() - t0_t1) * 1000

        if t1_res.success and t1_res.format != LogFormatEnum.UNSTRUCTURED:
            total_elapsed_ms = (time.perf_counter() - start_time) * 1000
            annotated = _annotate_telemetry(t1_res, route, tier_latencies, total_elapsed_ms)
            _cascade_metrics.record_hit(ParsingTierEnum.RULE, success=True)
            results[idx] = annotated
            continue

        # Tier 2 execution
        route.append("TIER_2")
        t0_t2 = time.perf_counter()
        try:
            t2_res = await parse_tier2_async(raw_log, tenant_id=tenant_id)
        except Exception as e:
            t2_res = ParsedResult(
                success=False,
                format=LogFormatEnum.UNSTRUCTURED,
                parsed_by=ParsingTierEnum.TEMPLATE,
                confidence=0.10,
                error_message=str(e),
            )
        tier_latencies["tier2_ms"] = (time.perf_counter() - t0_t2) * 1000

        # If not routing to LLM -> resolves in Phase 1
        if not should_route_to_llm(t2_res):
            total_elapsed_ms = (time.perf_counter() - start_time) * 1000
            annotated = _annotate_telemetry(t2_res, route, tier_latencies, total_elapsed_ms)
            _cascade_metrics.record_hit(ParsingTierEnum.TEMPLATE, success=t2_res.success)
            results[idx] = annotated
            continue

        # Novel log requiring Tier 3 -> enqueue for Phase 2 parallel dispatch
        route.append("TIER_3")
        pending_llm.append((idx, raw_log, t2_res, route, tier_latencies, start_time))

    # Phase 2: Concurrent Tier 3 Dispatch
    if pending_llm:
        async def _dispatch_single_llm(
            item: tuple[int, str, ParsedResult, list[str], dict[str, float], float],
        ) -> tuple[int, ParsedResult, list[str], dict[str, float], float]:
            target_idx, log_str, t2_intermediate, target_route, lats, item_start = item
            t0_t3 = time.perf_counter()
            try:
                t3_result = await parse_tier3_async(log_str, t2_intermediate, tenant_id=tenant_id)
            except Exception as e:
                logger.error("Batch Tier 3 worker error: %s", e)
                fallback_attrs = dict(t2_intermediate.attributes)
                fallback_attrs["tier3_failure"] = f"batch_llm_exception:{e}"
                t3_result = ParsedResult(
                    success=t2_intermediate.success,
                    format=t2_intermediate.format,
                    parsed_by=ParsingTierEnum.FALLBACK,
                    confidence=t2_intermediate.confidence,
                    action=t2_intermediate.action,
                    raw_timestamp=t2_intermediate.raw_timestamp,
                    severity=t2_intermediate.severity,
                    source=t2_intermediate.source,
                    destination=t2_intermediate.destination,
                    security=t2_intermediate.security,
                    attributes=fallback_attrs,
                    error_message=str(e),
                )
            lats["tier3_ms"] = (time.perf_counter() - t0_t3) * 1000
            if t3_result.parsed_by == ParsingTierEnum.FALLBACK:
                target_route.append("FALLBACK")
            return target_idx, t3_result, target_route, lats, item_start

        # Schedule all pending items concurrently
        llm_outcomes = await asyncio.gather(*[_dispatch_single_llm(item) for item in pending_llm])

        for target_idx, t3_res, target_route, lats, item_start in llm_outcomes:
            total_elapsed_ms = (time.perf_counter() - item_start) * 1000
            annotated = _annotate_telemetry(t3_res, target_route, lats, total_elapsed_ms)
            _cascade_metrics.record_hit(t3_res.parsed_by, success=t3_res.success)
            results[target_idx] = annotated

    # Reassembled output in exact original sequence
    return [r for r in results if r is not None]


def parse_cascade_batch(
    raw_logs: list[str],
    detected_formats: list[LogFormatEnum | None] | None = None,
    tenant_id: str | UUID | None = None,
) -> list[ParsedResult]:
    """Synchronous entry point for parse_cascade_batch_async."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(
                lambda: asyncio.run(
                    parse_cascade_batch_async(
                        raw_logs, detected_formats=detected_formats, tenant_id=tenant_id
                    )
                )
            ).result()
    else:
        return asyncio.run(
            parse_cascade_batch_async(
                raw_logs, detected_formats=detected_formats, tenant_id=tenant_id
            )
        )
