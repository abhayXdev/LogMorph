"""End-to-end integration tests for the composite Quality Normalization Pipeline.

Verifies the chained execution order:
1. Universal Timestamp Normalization
2. Field Cleaning & Data Sanitization
3. Tenant-Aware Deduplication

Validates full Golden Corpus E2E, order dependency (canonicalization before hashing),
PII leakage prevention in fingerprints, multi-tenant isolation, storm replay stress,
fault tolerance, and sub-millisecond SLA performance.
"""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from logmorph.config import settings
from logmorph.domain.uls import (
    DestinationInfo,
    LogFormatEnum,
    ParsingTierEnum,
    SeverityEnum,
    SourceInfo,
)
from logmorph.engine.normalizers.deduplicator import (
    DeduplicationMetrics,
    DeduplicationService,
    InMemoryDeduplicator,
    RedisDeduplicator,
    compute_event_fingerprint,
)
from logmorph.engine.normalizers.pipeline import (
    QualityPipeline,
    process_quality_pipeline_sync,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.engine.parsers.orchestrator import parse_cascade_async
from logmorph.schemas.pipeline import QualityPipelineConfig
from tests.fixtures.loader import load_ground_truth_corpus


@pytest.fixture
def isolated_pipeline() -> QualityPipeline:
    """Provide a QualityPipeline instance with an isolated in-memory deduplicator and metrics."""
    in_memory = InMemoryDeduplicator()
    metrics = DeduplicationMetrics()
    service = DeduplicationService(
        redis_deduplicator=RedisDeduplicator(redis_url=""),
        memory_deduplicator=in_memory,
        metrics=metrics,
    )
    return QualityPipeline(dedup_service=service)


# ==============================================================================
# 1. Full Golden Corpus E2E Pipeline Verification
# ==============================================================================


@pytest.mark.asyncio
async def test_golden_corpus_all_formats_through_quality_pipeline(
    isolated_pipeline: QualityPipeline,
) -> None:
    """Verify that every golden log format parses via Cascade and normalizes through QualityPipeline."""
    corpus = load_ground_truth_corpus()
    tenant_id = "tenant-golden-e2e"

    mock_response = MagicMock()
    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps({
        "action": "system_event",
        "severity": "ERROR",
        "summary": "Normalized unstructured log event",
        "attributes": {"pipeline": "quality_pipeline_e2e"},
    })
    mock_response.choices = [mock_choice]

    mock_client = AsyncMock()
    mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

    with (
        patch.object(settings, "NVIDIA_NIM_API_KEY", "nvapi-test"),
        patch("logmorph.engine.parsers.nim_client.get_nim_client", return_value=mock_client),
    ):
        for _log_format, samples in corpus.items():
            if not samples:
                continue
            sample_log = samples[0]

            # Step 1: Parse via 3-Tier Cascade
            parsed = await parse_cascade_async(sample_log, tenant_id=tenant_id)
            assert parsed.success is True

            # Step 2: Process through Quality Pipeline
            pipeline_res = await isolated_pipeline.process(
                result=parsed,
                tenant_id=tenant_id,
            )

            assert pipeline_res.success is True
            assert pipeline_res.pipeline_duration_ms >= 0.0

            final_parsed = pipeline_res.parsed_result
            attrs = final_parsed.attributes

            # Assert Universal Timestamp
            if pipeline_res.timestamp_result is not None:
                assert attrs.get("timestamp_normalized", "").endswith("Z")
                assert "timestamp_format" in attrs

            # Assert Deduplication Metadata
            assert attrs.get("is_duplicate") is False  # First encounter
            assert attrs.get("duplicate_count") == 1
            assert len(attrs.get("event_fingerprint", "")) == 64
            assert "dedup_backend" in attrs

            # Assert Endpoints are Clean
            if final_parsed.source and final_parsed.source.ip:
                assert not final_parsed.source.ip.startswith("0") or final_parsed.source.ip == "0.0.0.0"
                assert ":" not in final_parsed.source.ip or final_parsed.source.ip.count(":") >= 2


# ==============================================================================
# 2. Order Dependency Verification (Canonicalization BEFORE Fingerprinting)
# ==============================================================================


@pytest.mark.asyncio
async def test_order_dependency_canonicalization_before_deduplication(
    isolated_pipeline: QualityPipeline,
) -> None:
    """Logs differing ONLY in raw timestamp and uncleaned IP resolve to the SAME fingerprint."""
    tenant_id = "tenant-order-dep"

    # Log A: Apache CLF timestamp + IP with leading zeroes and port attached
    log_a = ParsedResult(
        success=True,
        format=LogFormatEnum.CLF,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="30/Oct/2026:14:15:20 +0000",
        severity=SeverityEnum.INFORMATIONAL,
        action="GET",
        source=SourceInfo(ip="192.168.001.050:8080", port=8080),
        destination=DestinationInfo(ip="10.000.001.001", port=443),
        attributes={"message": "HTTP request to /api/v1/health"},
    )

    # Log B: ISO 8601 UTC timestamp + already canonical RFC IP
    log_b = ParsedResult(
        success=True,
        format=LogFormatEnum.JSON,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="2026-10-30T14:15:20Z",
        severity=SeverityEnum.INFORMATIONAL,
        action="GET",
        source=SourceInfo(ip="192.168.1.50", port=8080),
        destination=DestinationInfo(ip="10.0.1.1", port=443),
        attributes={"message": "HTTP request to /api/v1/health"},
    )

    # Process Log A
    res_a = await isolated_pipeline.process(log_a, tenant_id=tenant_id)
    assert res_a.parsed_result.attributes["is_duplicate"] is False
    assert res_a.parsed_result.attributes["duplicate_count"] == 1
    fp_a = res_a.parsed_result.attributes["event_fingerprint"]

    # Process Log B: MUST be detected as duplicate of Log A
    res_b = await isolated_pipeline.process(log_b, tenant_id=tenant_id)
    assert res_b.parsed_result.attributes["is_duplicate"] is True
    assert res_b.parsed_result.attributes["duplicate_count"] == 2
    fp_b = res_b.parsed_result.attributes["event_fingerprint"]

    # Fingerprints must match exactly!
    assert fp_a == fp_b


# ==============================================================================
# 3. PII Redaction & Side-Channel Leakage Prevention
# ==============================================================================


@pytest.mark.asyncio
async def test_pii_sanitization_before_fingerprinting(
    isolated_pipeline: QualityPipeline,
) -> None:
    """PII secrets are redacted BEFORE deduplication, so fingerprints never hash raw credentials."""
    tenant_id = "tenant-pii-safe"

    raw_log = ParsedResult(
        success=True,
        format=LogFormatEnum.JSON,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="2026-10-30T10:00:00Z",
        severity=SeverityEnum.ERROR,
        action="PAYMENT_PROCESSED",
        source=SourceInfo(ip="10.0.0.5"),
        attributes={
            "message": "User admin paid with card 4532-0151-1283-0366 and token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak",
        },
    )

    res = await isolated_pipeline.process(raw_log, tenant_id=tenant_id)
    sanitized_msg = res.parsed_result.attributes["message"]

    # Verify PII is redacted in the message
    assert "4532-0151-1283-0366" not in sanitized_msg
    assert "[REDACTED_CREDIT_CARD]" in sanitized_msg
    assert "[REDACTED_JWT]" in sanitized_msg

    # Verify fingerprint is calculated from the redacted message
    expected_fp = compute_event_fingerprint(
        tenant_id=tenant_id,
        timestamp_str="2026-10-30T10:00:00Z",
        source_ip="10.0.0.5",
        action="PAYMENT_PROCESSED",
        message=sanitized_msg,
    )
    actual_fp = res.parsed_result.attributes["event_fingerprint"]
    assert actual_fp == expected_fp


# ==============================================================================
# 4. Multi-Tenant Quality Pipeline Isolation
# ==============================================================================


@pytest.mark.asyncio
async def test_multi_tenant_quality_pipeline_isolation(
    isolated_pipeline: QualityPipeline,
) -> None:
    """Identical logs arriving for Tenant Alpha and Tenant Beta remain strictly isolated."""
    log = ParsedResult(
        success=True,
        format=LogFormatEnum.CEF,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="2026-10-30T12:00:00Z",
        severity=SeverityEnum.WARNING,
        action="AUTH_ATTEMPT",
        source=SourceInfo(ip="203.0.113.195"),
        attributes={"message": "Failed password attempt"},
    )

    # Tenant Alpha - Event 1
    res_a1 = await isolated_pipeline.process(log, tenant_id="tenant-alpha")
    assert res_a1.parsed_result.attributes["is_duplicate"] is False
    assert res_a1.parsed_result.attributes["duplicate_count"] == 1

    # Tenant Beta - Event 1 (identical log, but different tenant)
    res_b1 = await isolated_pipeline.process(log, tenant_id="tenant-beta")
    assert res_b1.parsed_result.attributes["is_duplicate"] is False
    assert res_b1.parsed_result.attributes["duplicate_count"] == 1

    # Tenant Alpha - Event 2 (duplicate for Alpha)
    res_a2 = await isolated_pipeline.process(log, tenant_id="tenant-alpha")
    assert res_a2.parsed_result.attributes["is_duplicate"] is True
    assert res_a2.parsed_result.attributes["duplicate_count"] == 2

    # Tenant Beta - Event 2 (duplicate for Beta)
    res_b2 = await isolated_pipeline.process(log, tenant_id="tenant-beta")
    assert res_b2.parsed_result.attributes["is_duplicate"] is True
    assert res_b2.parsed_result.attributes["duplicate_count"] == 2


# ==============================================================================
# 5. Chaos & Storm Batch Replay Verification
# ==============================================================================


@pytest.mark.asyncio
async def test_storm_batch_replay_deduplication_stress(
    isolated_pipeline: QualityPipeline,
) -> None:
    """A storm of 500 duplicate records yields exactly 1 unique event and 499 duplicates."""
    tenant_id = "tenant-storm"
    burst_log = ParsedResult(
        success=True,
        format=LogFormatEnum.SYSLOG,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="Oct 30 14:15:20",
        severity=SeverityEnum.ERROR,
        action="CONN_TIMEOUT",
        source=SourceInfo(ip="10.20.30.40", port=5432),
        attributes={"message": "Database pool connection timeout on node-01"},
    )

    results = []
    for _ in range(500):
        res = await isolated_pipeline.process(burst_log, tenant_id=tenant_id)
        results.append(res)

    # First event is novel
    assert results[0].parsed_result.attributes["is_duplicate"] is False
    assert results[0].parsed_result.attributes["duplicate_count"] == 1

    # Next 499 events are duplicate
    for i in range(1, 500):
        assert results[i].parsed_result.attributes["is_duplicate"] is True
        assert results[i].parsed_result.attributes["duplicate_count"] == i + 1

    # Check metrics
    snapshot = isolated_pipeline._dedup_service.metrics.get_snapshot()
    assert snapshot.total_evaluated == 500
    assert snapshot.unique_events == 1
    assert snapshot.duplicates_suppressed == 499
    assert snapshot.suppression_rate_pct == 99.8


# ==============================================================================
# 6. Fault Tolerance & Missing/Malformed Fields
# ==============================================================================


@pytest.mark.asyncio
async def test_fault_tolerance_missing_fields_and_malformed_data(
    isolated_pipeline: QualityPipeline,
) -> None:
    """Pipeline gracefully handles logs with None/empty attributes without throwing exceptions."""
    tenant_id = "tenant-fault-tolerant"
    corrupt_log = ParsedResult(
        success=False,
        format=LogFormatEnum.UNSTRUCTURED,
        parsed_by=ParsingTierEnum.RULE,
        confidence=0.0,
        raw_timestamp=None,
        error_message="Syntax failure: Unrecognized log structure",
    )

    res = await isolated_pipeline.process(corrupt_log, tenant_id=tenant_id)
    assert res.success is True
    assert res.parsed_result.attributes["is_duplicate"] is False
    assert "event_fingerprint" in res.parsed_result.attributes


# ==============================================================================
# 7. Synchronous Processing & Global Toggle
# ==============================================================================


def test_quality_pipeline_sync_execution() -> None:
    """Synchronous pipeline runner executes seamlessly."""
    log = ParsedResult(
        success=True,
        format=LogFormatEnum.JSON,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="2026-10-30T10:00:00Z",
        severity=SeverityEnum.INFORMATIONAL,
        action="SYNC_TEST",
        attributes={"message": "Testing synchronous quality pipeline"},
    )

    res1 = process_quality_pipeline_sync(log, tenant_id="tenant-sync-pipeline")
    assert res1.success is True
    assert not res1.parsed_result.attributes["is_duplicate"]

    res2 = process_quality_pipeline_sync(log, tenant_id="tenant-sync-pipeline")
    assert res2.success is True
    assert res2.parsed_result.attributes["is_duplicate"]


def test_quality_pipeline_disabled_toggle() -> None:
    """When enabled=False, QualityPipeline passes through the parsed result without modification."""
    log = ParsedResult(
        success=True,
        format=LogFormatEnum.JSON,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="2026-10-30T10:00:00Z",
        severity=SeverityEnum.INFORMATIONAL,
        attributes={"message": "Raw log line"},
    )
    config = QualityPipelineConfig(enabled=False)
    res = process_quality_pipeline_sync(log, tenant_id="tenant-disabled", config=config)
    assert res.success is True
    assert "is_duplicate" not in res.parsed_result.attributes
    assert "timestamp_normalized" not in res.parsed_result.attributes


# ==============================================================================
# 8. High-Throughput Performance SLA Benchmark (< 1.0 ms / log)
# ==============================================================================


def test_quality_pipeline_performance_sla() -> None:
    """1,000 logs processed through the full quality pipeline must average < 1.0ms per log."""
    log = ParsedResult(
        success=True,
        format=LogFormatEnum.CEF,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="Oct 30 14:15:20",
        severity=SeverityEnum.INFORMATIONAL,
        action="PERF_TEST",
        source=SourceInfo(ip="192.168.001.050", port=8080),
        destination=DestinationInfo(ip="10.0.0.1", port=443),
        attributes={"message": "High throughput performance SLA verification"},
    )

    pipeline = QualityPipeline()
    tenant_id = "tenant-sla-perf"

    start = time.perf_counter()
    for _ in range(1000):
        pipeline.process_sync(log, tenant_id=tenant_id)
    duration = time.perf_counter() - start

    avg_ms = (duration / 1000.0) * 1000.0
    assert duration < 1.0, f"Took {duration:.4f}s for 1000 logs; expected < 1.0s"
    assert avg_ms < 1.0, f"Average pipeline latency {avg_ms:.3f}ms; expected < 1.0ms"
