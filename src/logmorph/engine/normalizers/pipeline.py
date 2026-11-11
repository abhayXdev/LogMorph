"""Composite Quality Normalization Pipeline Orchestrator.

Orchestrates the three core Day 4 quality stages in strict deterministic order:
1. Universal Timestamp Normalization (Standardizes to canonical UTC ISO-8601 'Z')
2. Field Cleaning & Data Sanitization (Endpoint canonicalization & PII scrubbing)
3. Tenant-Aware Deduplication (SHA-256 fingerprinting on sanitized payload + Redis/Memory sliding window)
"""

from __future__ import annotations

import logging
import time
from typing import Any

from logmorph.engine.normalizers.deduplicator import (
    DeduplicationService,
    compute_event_fingerprint,
    default_deduplication_service,
)
from logmorph.engine.normalizers.sanitizer import sanitize_parsed_result
from logmorph.engine.normalizers.timestamp import normalize_timestamp
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.pipeline import (
    QualityPipelineConfig,
    QualityPipelineResult,
)

logger = logging.getLogger(__name__)


class QualityPipeline:
    """Composite quality pipeline coordinating normalization, sanitization, and deduplication."""

    def __init__(
        self,
        dedup_service: DeduplicationService | None = None,
    ) -> None:
        self._dedup_service = dedup_service or default_deduplication_service

    async def process(
        self,
        result: ParsedResult,
        tenant_id: str,
        config: QualityPipelineConfig | None = None,
    ) -> QualityPipelineResult:
        """Process a ParsedResult through the full quality pipeline asynchronously."""
        start_time = time.perf_counter()
        cfg = config or QualityPipelineConfig()

        if not cfg.enabled:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return QualityPipelineResult(
                parsed_result=result,
                timestamp_result=None,
                sanitization_report=None,
                deduplication_result=None,
                pipeline_duration_ms=round(duration_ms, 3),
                success=True,
                tenant_id=tenant_id,
            )

        try:
            # ==============================================================
            # Stage 1: Universal Timestamp Normalization
            # ==============================================================
            ts_candidate = (
                result.raw_timestamp
                or result.attributes.get("timestamp")
                or result.attributes.get("time")
                or result.attributes.get("timestamp_normalized")
            )

            ts_result = None
            current_attributes: dict[str, Any] = dict(result.attributes)

            if ts_candidate is not None:
                ts_result = normalize_timestamp(
                    ts_candidate,
                    default_timezone=cfg.target_timezone,
                )
                current_attributes["timestamp_normalized"] = ts_result.iso_8601
                current_attributes["timestamp_format"] = ts_result.matched_format.value
                current_attributes["timestamp_was_fallback"] = ts_result.was_fallback

            result_with_ts = result.model_copy(
                update={"attributes": current_attributes},
            )

            # ==============================================================
            # Stage 2: Field Cleaning & Data Sanitization
            # ==============================================================
            sanitized_result, sanitization_report = sanitize_parsed_result(
                result=result_with_ts,
                config=cfg.field_cleaning,
            )

            # ==============================================================
            # Stage 3: Tenant-Aware Deduplication
            # ==============================================================
            norm_ts_str = (
                sanitized_result.attributes.get("timestamp_normalized")
                or sanitized_result.raw_timestamp
                or ""
            )
            src_ip = sanitized_result.source.ip if sanitized_result.source else None
            src_port = sanitized_result.source.port if sanitized_result.source else None
            dst_ip = (
                sanitized_result.destination.ip if sanitized_result.destination else None
            )
            dst_port = (
                sanitized_result.destination.port
                if sanitized_result.destination
                else None
            )
            action = sanitized_result.action
            message = (
                sanitized_result.attributes.get("message")
                or sanitized_result.attributes.get("raw_log")
                or sanitized_result.error_message
                or ""
            )

            fingerprint = compute_event_fingerprint(
                tenant_id=tenant_id,
                timestamp_str=norm_ts_str,
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                action=action,
                message=message,
            )

            dedup_res = await self._dedup_service.evaluate(
                tenant_id=tenant_id,
                fingerprint=fingerprint,
                config=cfg.deduplication,
            )

            final_attributes: dict[str, Any] = {
                **sanitized_result.attributes,
                "is_duplicate": dedup_res.is_duplicate,
                "duplicate_count": dedup_res.duplicate_count,
                "event_fingerprint": dedup_res.fingerprint,
                "dedup_backend": dedup_res.storage_backend.value,
            }

            final_result = sanitized_result.model_copy(
                update={"attributes": final_attributes},
            )

            duration_ms = (time.perf_counter() - start_time) * 1000.0

            return QualityPipelineResult(
                parsed_result=final_result,
                timestamp_result=ts_result,
                sanitization_report=sanitization_report,
                deduplication_result=dedup_res,
                pipeline_duration_ms=round(duration_ms, 3),
                success=True,
                tenant_id=tenant_id,
            )

        except Exception as exc:
            logger.exception("Unexpected error during Quality Pipeline execution: %s", exc)
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_attributes = {
                **result.attributes,
                "quality_pipeline_error": str(exc),
            }
            error_result = result.model_copy(update={"attributes": error_attributes})
            return QualityPipelineResult(
                parsed_result=error_result,
                timestamp_result=None,
                sanitization_report=None,
                deduplication_result=None,
                pipeline_duration_ms=round(duration_ms, 3),
                success=False,
                tenant_id=tenant_id,
            )

    def process_sync(
        self,
        result: ParsedResult,
        tenant_id: str,
        config: QualityPipelineConfig | None = None,
    ) -> QualityPipelineResult:
        """Process a ParsedResult through the full quality pipeline synchronously."""
        start_time = time.perf_counter()
        cfg = config or QualityPipelineConfig()

        if not cfg.enabled:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return QualityPipelineResult(
                parsed_result=result,
                timestamp_result=None,
                sanitization_report=None,
                deduplication_result=None,
                pipeline_duration_ms=round(duration_ms, 3),
                success=True,
                tenant_id=tenant_id,
            )

        try:
            # Stage 1: Timestamp Normalization
            ts_candidate = (
                result.raw_timestamp
                or result.attributes.get("timestamp")
                or result.attributes.get("time")
                or result.attributes.get("timestamp_normalized")
            )

            ts_result = None
            current_attributes: dict[str, Any] = dict(result.attributes)

            if ts_candidate is not None:
                ts_result = normalize_timestamp(
                    ts_candidate,
                    default_timezone=cfg.target_timezone,
                )
                current_attributes["timestamp_normalized"] = ts_result.iso_8601
                current_attributes["timestamp_format"] = ts_result.matched_format.value
                current_attributes["timestamp_was_fallback"] = ts_result.was_fallback

            result_with_ts = result.model_copy(
                update={"attributes": current_attributes},
            )

            # Stage 2: Field Cleaning & Data Sanitization
            sanitized_result, sanitization_report = sanitize_parsed_result(
                result=result_with_ts,
                config=cfg.field_cleaning,
            )

            # Stage 3: Tenant-Aware Deduplication (Synchronous In-Memory Fallback)
            norm_ts_str = (
                sanitized_result.attributes.get("timestamp_normalized")
                or sanitized_result.raw_timestamp
                or ""
            )
            src_ip = sanitized_result.source.ip if sanitized_result.source else None
            src_port = sanitized_result.source.port if sanitized_result.source else None
            dst_ip = (
                sanitized_result.destination.ip if sanitized_result.destination else None
            )
            dst_port = (
                sanitized_result.destination.port
                if sanitized_result.destination
                else None
            )
            action = sanitized_result.action
            message = (
                sanitized_result.attributes.get("message")
                or sanitized_result.attributes.get("raw_log")
                or sanitized_result.error_message
                or ""
            )

            fingerprint = compute_event_fingerprint(
                tenant_id=tenant_id,
                timestamp_str=norm_ts_str,
                source_ip=src_ip,
                source_port=src_port,
                destination_ip=dst_ip,
                destination_port=dst_port,
                action=action,
                message=message,
            )

            dedup_res = self._dedup_service.evaluate_sync(
                tenant_id=tenant_id,
                fingerprint=fingerprint,
                config=cfg.deduplication,
            )

            final_attributes: dict[str, Any] = {
                **sanitized_result.attributes,
                "is_duplicate": dedup_res.is_duplicate,
                "duplicate_count": dedup_res.duplicate_count,
                "event_fingerprint": dedup_res.fingerprint,
                "dedup_backend": dedup_res.storage_backend.value,
            }

            final_result = sanitized_result.model_copy(
                update={"attributes": final_attributes},
            )

            duration_ms = (time.perf_counter() - start_time) * 1000.0

            return QualityPipelineResult(
                parsed_result=final_result,
                timestamp_result=ts_result,
                sanitization_report=sanitization_report,
                deduplication_result=dedup_res,
                pipeline_duration_ms=round(duration_ms, 3),
                success=True,
                tenant_id=tenant_id,
            )

        except Exception as exc:
            logger.exception("Unexpected error during sync Quality Pipeline execution: %s", exc)
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_attributes = {
                **result.attributes,
                "quality_pipeline_error": str(exc),
            }
            error_result = result.model_copy(update={"attributes": error_attributes})
            return QualityPipelineResult(
                parsed_result=error_result,
                timestamp_result=None,
                sanitization_report=None,
                deduplication_result=None,
                pipeline_duration_ms=round(duration_ms, 3),
                success=False,
                tenant_id=tenant_id,
            )


# Default quality pipeline singleton
default_quality_pipeline = QualityPipeline()


async def process_quality_pipeline(
    result: ParsedResult,
    tenant_id: str,
    config: QualityPipelineConfig | None = None,
    dedup_service: DeduplicationService | None = None,
) -> QualityPipelineResult:
    """Convenience function to execute the full quality normalization pipeline asynchronously."""
    pipeline = (
        QualityPipeline(dedup_service=dedup_service)
        if dedup_service
        else default_quality_pipeline
    )
    return await pipeline.process(result, tenant_id=tenant_id, config=config)


def process_quality_pipeline_sync(
    result: ParsedResult,
    tenant_id: str,
    config: QualityPipelineConfig | None = None,
    dedup_service: DeduplicationService | None = None,
) -> QualityPipelineResult:
    """Convenience function to execute the full quality normalization pipeline synchronously."""
    pipeline = (
        QualityPipeline(dedup_service=dedup_service)
        if dedup_service
        else default_quality_pipeline
    )
    return pipeline.process_sync(result, tenant_id=tenant_id, config=config)
