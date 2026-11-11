"""Unified LogMorph Engine Core Assembly.

Orchestrates the entire multi-stage processing pipeline:
1. Format Detection (Rules & Heuristics)
2. Adaptive Parsing Cascade (Tier 1 Rules -> Tier 2 Drain3 -> Tier 3 NVIDIA NIM / Fallback)
3. Quality & Normalization (Timestamp Normalization + Field Sanitization + Deduplication)
4. Contextual Enrichment (GeoIP + Threat Intel + MITRE ATT&CK)
5. Telemetry & Observability Aggregation
"""

from __future__ import annotations

import collections
import concurrent.futures
import logging
import threading
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from logmorph.domain.uls import (
    LogFormatEnum,
    ParsingTierEnum,
    SeverityEnum,
    UniversalLogEvent,
)
from logmorph.engine.detector import detect_format
from logmorph.engine.enrichers.geoip import GeoIPAdapter, get_geoip_adapter
from logmorph.engine.enrichers.mitre import MitreAttackTagger, get_mitre_tagger
from logmorph.engine.enrichers.threat_intel import (
    ThreatIntelMatcher,
    get_threat_intel_matcher,
)
from logmorph.engine.normalizers.pipeline import (
    QualityPipeline,
    default_quality_pipeline,
)
from logmorph.engine.parsers.orchestrator import (
    parse_cascade,
    parse_cascade_async,
)
from logmorph.schemas.engine import (
    EngineConfig,
    EngineMetricsSnapshot,
    EngineProcessingResult,
)
from logmorph.schemas.pipeline import QualityPipelineConfig

logger = logging.getLogger(__name__)


# ==============================================================================
# 1. Thread-Safe Telemetry Aggregator
# ==============================================================================


class EngineMetrics:
    """Thread-safe telemetry accumulator for the unified processing engine."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_processed: int = 0
        self._successful: int = 0
        self._failed: int = 0
        self._duplicates: int = 0
        self._threats: int = 0
        self._mitre_tags: int = 0
        self._format_counts: dict[str, int] = {}
        self._tier_counts: dict[str, int] = {}
        self._latencies: collections.deque[float] = collections.deque(maxlen=10000)

    def record(
        self,
        success: bool,
        is_duplicate: bool,
        threat_matched: bool,
        mitre_tagged: bool,
        latency_ms: float,
        fmt: LogFormatEnum | None = None,
        tier: ParsingTierEnum | None = None,
    ) -> None:
        """Record the outcome and telemetry of an individual log processing turn."""
        with self._lock:
            self._total_processed += 1
            if success:
                self._successful += 1
            else:
                self._failed += 1

            if is_duplicate:
                self._duplicates += 1
            if threat_matched:
                self._threats += 1
            if mitre_tagged:
                self._mitre_tags += 1

            if fmt:
                fmt_key = fmt.value if hasattr(fmt, "value") else str(fmt)
                self._format_counts[fmt_key] = (
                    self._format_counts.get(fmt_key, 0) + 1
                )
            if tier:
                tier_key = tier.value if hasattr(tier, "value") else str(tier)
                self._tier_counts[tier_key] = (
                    self._tier_counts.get(tier_key, 0) + 1
                )

            self._latencies.append(latency_ms)

    def get_snapshot(self) -> EngineMetricsSnapshot:
        """Produce an immutable point-in-time metrics snapshot with percentile calculations."""
        with self._lock:
            n = len(self._latencies)
            if n == 0:
                avg_lat = 0.0
                p95_lat = 0.0
                p99_lat = 0.0
            else:
                sorted_lats = sorted(self._latencies)
                avg_lat = round(sum(sorted_lats) / n, 3)
                p95_idx = min(int(n * 0.95), n - 1)
                p99_idx = min(int(n * 0.99), n - 1)
                p95_lat = round(sorted_lats[p95_idx], 3)
                p99_lat = round(sorted_lats[p99_idx], 3)

            return EngineMetricsSnapshot(
                total_processed=self._total_processed,
                successful=self._successful,
                failed=self._failed,
                duplicates_detected=self._duplicates,
                threats_detected=self._threats,
                mitre_tagged=self._mitre_tags,
                avg_latency_ms=avg_lat,
                p95_latency_ms=p95_lat,
                p99_latency_ms=p99_lat,
                format_breakdown=dict(self._format_counts),
                tier_breakdown=dict(self._tier_counts),
            )

    def reset(self) -> None:
        """Reset all counters and latency buffers."""
        with self._lock:
            self._total_processed = 0
            self._successful = 0
            self._failed = 0
            self._duplicates = 0
            self._threats = 0
            self._mitre_tags = 0
            self._format_counts.clear()
            self._tier_counts.clear()
            self._latencies.clear()


# Global singleton engine metrics collector
engine_metrics = EngineMetrics()


# ==============================================================================
# 2. Unified LogMorph Engine
# ==============================================================================


class LogMorphEngine:
    """Unified core processing engine for LogMorph.

    Integrates format detection, adaptive parsing cascade, quality normalization,
    and contextual enrichment into an enterprise pipeline.
    """

    def __init__(
        self,
        config: EngineConfig | None = None,
        metrics: EngineMetrics | None = None,
        quality_pipeline: QualityPipeline | None = None,
        geoip_adapter: GeoIPAdapter | None = None,
        threat_intel_matcher: ThreatIntelMatcher | None = None,
        mitre_tagger: MitreAttackTagger | None = None,
    ) -> None:
        self._config = config or EngineConfig()
        self._metrics = metrics or engine_metrics
        self._quality_pipeline = quality_pipeline or default_quality_pipeline
        self._geoip_adapter = geoip_adapter or get_geoip_adapter()
        self._threat_intel_matcher = (
            threat_intel_matcher or get_threat_intel_matcher()
        )
        self._mitre_tagger = mitre_tagger or get_mitre_tagger()

    @property
    def config(self) -> EngineConfig:
        return self._config

    @property
    def metrics(self) -> EngineMetrics:
        return self._metrics

    def _resolve_tenant_uuid(self, tenant_id: UUID | str) -> UUID:
        """Safely coerce tenant identifier to standard UUID."""
        if isinstance(tenant_id, UUID):
            return tenant_id
        return UUID(str(tenant_id))

    def _build_universal_event(
        self,
        raw_log: str,
        tenant_uuid: UUID,
        det_format: LogFormatEnum,
        attributes: dict[str, Any],
        source: Any,
        destination: Any,
        security: Any,
        action: str | None,
        parsed_by: ParsingTierEnum,
        severity: SeverityEnum,
    ) -> UniversalLogEvent:
        """Construct the canonical UniversalLogEvent with normalized UTC timestamp."""
        iso_ts = attributes.get("timestamp_normalized")
        event_dt = datetime.now(UTC)
        if iso_ts and isinstance(iso_ts, str):
            try:
                event_dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
            except ValueError:
                event_dt = datetime.now(UTC)

        return UniversalLogEvent(
            tenant_id=tenant_uuid,
            timestamp=event_dt,
            raw_log=raw_log,
            detected_format=det_format,
            severity=severity or SeverityEnum.INFORMATIONAL,
            source=source,
            destination=destination,
            security=security,
            action=action,
            parsed_by=parsed_by or ParsingTierEnum.RULE,
            attributes=attributes,
        )

    def _apply_enrichment(
        self,
        event: UniversalLogEvent,
    ) -> UniversalLogEvent:
        """Apply configured contextual enrichers in deterministic sequence."""
        if self._config.geoip_enabled:
            event = self._geoip_adapter.enrich_event(event)

        if self._config.threat_intel_enabled:
            event = self._threat_intel_matcher.enrich_event(event)

        if self._config.mitre_tagger_enabled:
            event = self._mitre_tagger.enrich_event(event)

        return event

    def process(
        self,
        raw_log: str,
        tenant_id: UUID | str,
    ) -> EngineProcessingResult:
        """Synchronously process a single log string through the unified pipeline."""
        start_time = time.perf_counter()

        # Gate 0: Validate input
        if not raw_log or not raw_log.strip():
            self._metrics.record(
                success=False,
                is_duplicate=False,
                threat_matched=False,
                mitre_tagged=False,
                latency_ms=0.0,
            )
            return EngineProcessingResult(
                success=False,
                error_message="Empty or whitespace-only log string.",
                latency_ms=0.0,
            )

        try:
            tenant_uuid = self._resolve_tenant_uuid(tenant_id)
        except Exception as exc:
            self._metrics.record(
                success=False,
                is_duplicate=False,
                threat_matched=False,
                mitre_tagged=False,
                latency_ms=0.0,
            )
            return EngineProcessingResult(
                success=False,
                error_message=f"Invalid tenant UUID: {exc}",
                latency_ms=0.0,
            )

        try:
            # Stage 1: Format Detection
            if self._config.detection_enabled:
                det_res = detect_format(raw_log)
                det_format = det_res.detected_format
            else:
                det_format = LogFormatEnum.UNSTRUCTURED

            # Stage 2: Adaptive Parsing Cascade
            if self._config.cascade_enabled:
                parsed_res = parse_cascade(
                    raw_log=raw_log,
                    detected_format=det_format,
                    tenant_id=tenant_uuid,
                )
            else:
                parsed_res = parse_cascade(
                    raw_log=raw_log,
                    detected_format=LogFormatEnum.UNSTRUCTURED,
                    tenant_id=tenant_uuid,
                )

            # Stage 3: Quality Normalization Pipeline
            qp_config = QualityPipelineConfig(
                enabled=self._config.quality_pipeline_enabled,
                deduplication=QualityPipelineConfig().deduplication.model_copy(
                    update={"enabled": self._config.deduplication_enabled}
                ),
            )
            quality_res = self._quality_pipeline.process_sync(
                result=parsed_res,
                tenant_id=str(tenant_uuid),
                config=qp_config,
            )

            final_parsed = quality_res.parsed_result
            is_dup = bool(final_parsed.attributes.get("is_duplicate", False))

            # Deduplication drop check
            if is_dup and self._config.drop_duplicates:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                self._metrics.record(
                    success=True,
                    is_duplicate=True,
                    threat_matched=False,
                    mitre_tagged=False,
                    latency_ms=elapsed_ms,
                    fmt=det_format,
                    tier=final_parsed.parsed_by,
                )
                return EngineProcessingResult(
                    success=True,
                    event=None,
                    latency_ms=round(elapsed_ms, 3),
                    format_detected=det_format,
                    parsed_by=final_parsed.parsed_by,
                    is_duplicate=True,
                )

            # Assemble Canonical UniversalLogEvent
            event = self._build_universal_event(
                raw_log=raw_log,
                tenant_uuid=tenant_uuid,
                det_format=det_format,
                attributes=dict(final_parsed.attributes),
                source=final_parsed.source,
                destination=final_parsed.destination,
                security=final_parsed.security,
                action=final_parsed.action,
                parsed_by=final_parsed.parsed_by,
                severity=final_parsed.severity,
            )

            # Stage 4: Contextual Enrichment
            event = self._apply_enrichment(event)

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            threat_matched = bool(event.enrichment and event.enrichment.threat_match)
            mitre_tech = (
                event.enrichment.mitre_technique if event.enrichment else None
            )
            geoip_country = (
                event.enrichment.geoip.country
                if (event.enrichment and event.enrichment.geoip)
                else None
            )

            self._metrics.record(
                success=True,
                is_duplicate=is_dup,
                threat_matched=threat_matched,
                mitre_tagged=bool(mitre_tech),
                latency_ms=elapsed_ms,
                fmt=det_format,
                tier=event.parsed_by,
            )

            return EngineProcessingResult(
                success=True,
                event=event,
                latency_ms=round(elapsed_ms, 3),
                format_detected=det_format,
                parsed_by=event.parsed_by,
                is_duplicate=is_dup,
                threat_matched=threat_matched,
                mitre_technique=mitre_tech,
                geoip_country=geoip_country,
            )

        except Exception as exc:
            logger.exception("Unified engine failed to process log: %s", exc)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            self._metrics.record(
                success=False,
                is_duplicate=False,
                threat_matched=False,
                mitre_tagged=False,
                latency_ms=elapsed_ms,
            )
            return EngineProcessingResult(
                success=False,
                error_message=str(exc),
                latency_ms=round(elapsed_ms, 3),
            )

    async def process_async(
        self,
        raw_log: str,
        tenant_id: UUID | str,
    ) -> EngineProcessingResult:
        """Asynchronously process a single log string through the unified pipeline."""
        start_time = time.perf_counter()

        if not raw_log or not raw_log.strip():
            self._metrics.record(
                success=False,
                is_duplicate=False,
                threat_matched=False,
                mitre_tagged=False,
                latency_ms=0.0,
            )
            return EngineProcessingResult(
                success=False,
                error_message="Empty or whitespace-only log string.",
                latency_ms=0.0,
            )

        try:
            tenant_uuid = self._resolve_tenant_uuid(tenant_id)
        except Exception as exc:
            self._metrics.record(
                success=False,
                is_duplicate=False,
                threat_matched=False,
                mitre_tagged=False,
                latency_ms=0.0,
            )
            return EngineProcessingResult(
                success=False,
                error_message=f"Invalid tenant UUID: {exc}",
                latency_ms=0.0,
            )

        try:
            # Stage 1: Detection
            if self._config.detection_enabled:
                det_res = detect_format(raw_log)
                det_format = det_res.detected_format
            else:
                det_format = LogFormatEnum.UNSTRUCTURED

            # Stage 2: Cascade Parsing
            if self._config.cascade_enabled:
                parsed_res = await parse_cascade_async(
                    raw_log=raw_log,
                    detected_format=det_format,
                    tenant_id=tenant_uuid,
                )
            else:
                parsed_res = await parse_cascade_async(
                    raw_log=raw_log,
                    detected_format=LogFormatEnum.UNSTRUCTURED,
                    tenant_id=tenant_uuid,
                )

            # Stage 3: Quality Normalization
            qp_config = QualityPipelineConfig(
                enabled=self._config.quality_pipeline_enabled,
                deduplication=QualityPipelineConfig().deduplication.model_copy(
                    update={"enabled": self._config.deduplication_enabled}
                ),
            )
            quality_res = await self._quality_pipeline.process(
                result=parsed_res,
                tenant_id=str(tenant_uuid),
                config=qp_config,
            )

            final_parsed = quality_res.parsed_result
            is_dup = bool(final_parsed.attributes.get("is_duplicate", False))

            if is_dup and self._config.drop_duplicates:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                self._metrics.record(
                    success=True,
                    is_duplicate=True,
                    threat_matched=False,
                    mitre_tagged=False,
                    latency_ms=elapsed_ms,
                    fmt=det_format,
                    tier=final_parsed.parsed_by,
                )
                return EngineProcessingResult(
                    success=True,
                    event=None,
                    latency_ms=round(elapsed_ms, 3),
                    format_detected=det_format,
                    parsed_by=final_parsed.parsed_by,
                    is_duplicate=True,
                )

            event = self._build_universal_event(
                raw_log=raw_log,
                tenant_uuid=tenant_uuid,
                det_format=det_format,
                attributes=dict(final_parsed.attributes),
                source=final_parsed.source,
                destination=final_parsed.destination,
                security=final_parsed.security,
                action=final_parsed.action,
                parsed_by=final_parsed.parsed_by,
                severity=final_parsed.severity,
            )

            # Stage 4: Enrichment
            event = self._apply_enrichment(event)

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            threat_matched = bool(event.enrichment and event.enrichment.threat_match)
            mitre_tech = (
                event.enrichment.mitre_technique if event.enrichment else None
            )
            geoip_country = (
                event.enrichment.geoip.country
                if (event.enrichment and event.enrichment.geoip)
                else None
            )

            self._metrics.record(
                success=True,
                is_duplicate=is_dup,
                threat_matched=threat_matched,
                mitre_tagged=bool(mitre_tech),
                latency_ms=elapsed_ms,
                fmt=det_format,
                tier=event.parsed_by,
            )

            return EngineProcessingResult(
                success=True,
                event=event,
                latency_ms=round(elapsed_ms, 3),
                format_detected=det_format,
                parsed_by=event.parsed_by,
                is_duplicate=is_dup,
                threat_matched=threat_matched,
                mitre_technique=mitre_tech,
                geoip_country=geoip_country,
            )

        except Exception as exc:
            logger.exception("Unified engine failed in async processing: %s", exc)
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            self._metrics.record(
                success=False,
                is_duplicate=False,
                threat_matched=False,
                mitre_tagged=False,
                latency_ms=elapsed_ms,
            )
            return EngineProcessingResult(
                success=False,
                error_message=str(exc),
                latency_ms=round(elapsed_ms, 3),
            )

    def process_batch(
        self,
        raw_logs: list[str],
        tenant_id: UUID | str,
    ) -> list[EngineProcessingResult]:
        """Process a batch of logs concurrently using a worker pool."""
        if not raw_logs:
            return []

        workers = min(self._config.max_batch_workers, len(raw_logs))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self.process, raw_log, tenant_id)
                for raw_log in raw_logs
            ]
            return [f.result() for f in futures]

    async def process_batch_async(
        self,
        raw_logs: list[str],
        tenant_id: UUID | str,
    ) -> list[EngineProcessingResult]:
        """Process a batch of logs asynchronously in parallel."""
        import asyncio

        if not raw_logs:
            return []

        tasks = [self.process_async(raw_log, tenant_id) for raw_log in raw_logs]
        return await asyncio.gather(*tasks)

    def get_metrics(self) -> EngineMetricsSnapshot:
        """Return point-in-time metrics snapshot."""
        return self._metrics.get_snapshot()

    def reset_metrics(self) -> None:
        """Reset internal metrics."""
        self._metrics.reset()


# ==============================================================================
# 3. Global Factory / Singleton Accessor
# ==============================================================================

_global_engine: LogMorphEngine | None = None
_global_engine_lock = threading.Lock()


def get_engine() -> LogMorphEngine:
    """Return the global shared singleton LogMorphEngine instance."""
    global _global_engine
    if _global_engine is None:
        with _global_engine_lock:
            if _global_engine is None:
                _global_engine = LogMorphEngine()
    return _global_engine
