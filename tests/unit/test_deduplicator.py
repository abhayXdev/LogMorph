"""Comprehensive unit test suite for tenant-aware sliding-window deduplication.

Tests deterministic SHA-256 fingerprinting, strict multi-tenant isolation,
sliding-window counter tracking, TTL expiration, autonomous in-memory fallback,
capacity bounds, telemetry metrics audit, and performance SLA.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

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
    deduplicate_parsed_result,
)
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.deduplication import (
    DeduplicationBackendEnum,
    DeduplicationConfig,
)

# ==============================================================================
# 1. Fingerprint Determinism & Collision Resistance Tests
# ==============================================================================


def test_fingerprint_determinism_identical_inputs() -> None:
    """Identical inputs must yield identical 64-char hexadecimal SHA-256 digests."""
    fp1 = compute_event_fingerprint(
        tenant_id="tenant-alpha",
        timestamp_str="2026-10-30T10:00:00Z",
        source_ip="192.168.1.100",
        source_port=8080,
        destination_ip="10.0.0.1",
        destination_port=443,
        action="LOGIN_FAILED",
        message="Bad credentials for user admin",
    )
    fp2 = compute_event_fingerprint(
        tenant_id="tenant-alpha",
        timestamp_str="2026-10-30T10:00:00Z",
        source_ip="192.168.1.100",
        source_port=8080,
        destination_ip="10.0.0.1",
        destination_port=443,
        action="LOGIN_FAILED",
        message="Bad credentials for user admin",
    )
    assert len(fp1) == 64
    assert fp1 == fp2


def test_fingerprint_normalization_whitespace_and_case() -> None:
    """Action should be normalized to uppercase; trailing whitespaces trimmed."""
    fp_raw = compute_event_fingerprint(
        tenant_id=" tenant-alpha ",
        action="login_failed",
        message=" test message ",
    )
    fp_normalized = compute_event_fingerprint(
        tenant_id="tenant-alpha",
        action="LOGIN_FAILED",
        message="test message",
    )
    assert fp_raw == fp_normalized


def test_fingerprint_differentiates_tenants() -> None:
    """Events identical in all aspects except tenant_id must produce distinct fingerprints."""
    fp_a = compute_event_fingerprint(
        tenant_id="tenant-a",
        timestamp_str="2026-10-30T10:00:00Z",
        source_ip="1.2.3.4",
        action="DROP",
    )
    fp_b = compute_event_fingerprint(
        tenant_id="tenant-b",
        timestamp_str="2026-10-30T10:00:00Z",
        source_ip="1.2.3.4",
        action="DROP",
    )
    assert fp_a != fp_b


def test_fingerprint_differentiates_endpoints_and_actions() -> None:
    """Differences in IP, port, action, or message must alter the fingerprint."""
    base_args = {
        "tenant_id": "tenant-alpha",
        "timestamp_str": "2026-10-30T10:00:00Z",
        "source_ip": "1.2.3.4",
        "source_port": 80,
        "destination_ip": "5.6.7.8",
        "destination_port": 443,
        "action": "ACCEPT",
        "message": "allowed",
    }
    base_fp = compute_event_fingerprint(**base_args)  # type: ignore[arg-type]

    # Change source IP
    assert compute_event_fingerprint(**{**base_args, "source_ip": "1.2.3.5"}) != base_fp  # type: ignore[arg-type]
    # Change port
    assert compute_event_fingerprint(**{**base_args, "source_port": 81}) != base_fp  # type: ignore[arg-type]
    # Change action
    assert compute_event_fingerprint(**{**base_args, "action": "REJECT"}) != base_fp  # type: ignore[arg-type]
    # Change message
    assert compute_event_fingerprint(**{**base_args, "message": "denied"}) != base_fp  # type: ignore[arg-type]


# ==============================================================================
# 2. In-Memory Sliding-Window Deduplicator Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_in_memory_duplicate_tracking_counter() -> None:
    """Consecutive evaluations of the same fingerprint increment count and flag duplicates."""
    mem = InMemoryDeduplicator()
    tenant = "tenant-test"
    fp = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

    # 1st observation: Novel
    is_dup, count = await mem.evaluate(tenant, fp, ttl_seconds=10)
    assert not is_dup
    assert count == 1

    # 2nd observation: Duplicate
    is_dup, count = await mem.evaluate(tenant, fp, ttl_seconds=10)
    assert is_dup
    assert count == 2

    # 3rd observation: Duplicate
    is_dup, count = await mem.evaluate(tenant, fp, ttl_seconds=10)
    assert is_dup
    assert count == 3


def test_in_memory_sync_evaluation() -> None:
    """Synchronous evaluation path works identically to async."""
    mem = InMemoryDeduplicator()
    tenant = "tenant-sync"
    fp = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"

    is_dup, count = mem.evaluate_sync(tenant, fp, ttl_seconds=60)
    assert not is_dup
    assert count == 1

    is_dup, count = mem.evaluate_sync(tenant, fp, ttl_seconds=60)
    assert is_dup
    assert count == 2


@pytest.mark.asyncio
async def test_in_memory_multi_tenant_isolation() -> None:
    """Identical fingerprints for Tenant A and Tenant B must track independently."""
    mem = InMemoryDeduplicator()
    fp = "sharedfingerprint1234567890abcdef1234567890abcdef1234567890abcdef"

    # Tenant A - 1st
    is_dup_a, count_a = await mem.evaluate("tenant-a", fp)
    assert not is_dup_a
    assert count_a == 1

    # Tenant B - 1st (identical fingerprint, but different tenant)
    is_dup_b, count_b = await mem.evaluate("tenant-b", fp)
    assert not is_dup_b
    assert count_b == 1

    # Tenant A - 2nd
    is_dup_a2, count_a2 = await mem.evaluate("tenant-a", fp)
    assert is_dup_a2
    assert count_a2 == 2

    # Tenant B still at 1
    assert mem._cache["tenant-b:" + fp][1] == 1


@pytest.mark.asyncio
async def test_in_memory_ttl_expiration() -> None:
    """After sliding window TTL passes, subsequent observations reset counter to 1."""
    mem = InMemoryDeduplicator()
    tenant = "tenant-ttl"
    fp = "ttlexpirefingerprint1234567890abcdef1234567890abcdef1234567890"

    # Register with short 1-second TTL
    is_dup, count = await mem.evaluate(tenant, fp, ttl_seconds=1)
    assert not is_dup
    assert count == 1

    # Manually backdate the entry's monotonic expiry to simulate time passage
    mem._cache[f"{tenant}:{fp}"] = (time.monotonic() - 0.1, count)

    # Next observation should now be treated as novel
    is_dup_expired, count_expired = await mem.evaluate(tenant, fp, ttl_seconds=60)
    assert not is_dup_expired
    assert count_expired == 1


@pytest.mark.asyncio
async def test_in_memory_capacity_bounding_and_eviction() -> None:
    """When capacity is reached, expired items and oldest items are evicted."""
    mem = InMemoryDeduplicator(max_entries=5)
    tenant = "tenant-cap"

    # Insert 5 entries
    for i in range(5):
        await mem.evaluate(tenant, f"fp-{i}", ttl_seconds=60)
    assert mem.size == 5

    # Insert 6th entry: should trigger eviction of oldest
    await mem.evaluate(tenant, "fp-5", ttl_seconds=60)
    assert mem.size <= 5
    assert "tenant-cap:fp-5" in mem._cache


# ==============================================================================
# 3. Redis Deduplicator & Resilience Fallback Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_redis_deduplicator_atomic_lua_execution() -> None:
    """Redis Lua script evaluates novel and duplicate counts properly."""
    mock_client = AsyncMock()
    mock_client.script_load = AsyncMock(return_value="fake_sha_123")
    mock_client.evalsha = AsyncMock(side_effect=[1, 2])

    redis_dedup = RedisDeduplicator(client=mock_client)
    res1 = await redis_dedup.evaluate("tenant-red", "fp123", ttl_seconds=60)
    assert res1 == (False, 1)

    res2 = await redis_dedup.evaluate("tenant-red", "fp123", ttl_seconds=60)
    assert res2 == (True, 2)


@pytest.mark.asyncio
async def test_redis_deduplicator_connection_failure_returns_none() -> None:
    """When Redis raises RedisConnectionError, evaluate gracefully returns None."""
    mock_client = AsyncMock()
    mock_client.script_load = AsyncMock(side_effect=RedisConnectionError("Connection refused"))

    redis_dedup = RedisDeduplicator(client=mock_client)
    res = await redis_dedup.evaluate("tenant-err", "fp123")
    assert res is None


@pytest.mark.asyncio
async def test_service_seamless_fallback_to_memory_when_redis_offline() -> None:
    """DeduplicationService falls back to memory backend when Redis fails."""
    mock_client = AsyncMock()
    mock_client.script_load = AsyncMock(side_effect=RedisConnectionError("Redis down"))

    redis_dedup = RedisDeduplicator(client=mock_client)
    mem_dedup = InMemoryDeduplicator()
    metrics = DeduplicationMetrics()
    service = DeduplicationService(
        redis_deduplicator=redis_dedup,
        memory_deduplicator=mem_dedup,
        metrics=metrics,
    )

    res1 = await service.evaluate("tenant-fall", "fp-fallback")
    assert not res1.is_duplicate
    assert res1.duplicate_count == 1
    assert res1.storage_backend == DeduplicationBackendEnum.MEMORY_FALLBACK

    res2 = await service.evaluate("tenant-fall", "fp-fallback")
    assert res2.is_duplicate
    assert res2.duplicate_count == 2
    assert res2.storage_backend == DeduplicationBackendEnum.MEMORY_FALLBACK

    snapshot = metrics.get_snapshot()
    assert snapshot.total_evaluated == 2
    assert snapshot.unique_events == 1
    assert snapshot.duplicates_suppressed == 1
    assert snapshot.memory_fallback_hits == 2
    assert snapshot.redis_hits == 0


@pytest.mark.asyncio
async def test_service_routes_to_redis_when_available() -> None:
    """When Redis is reachable, DeduplicationService records REDIS backend."""
    mock_client = AsyncMock()
    mock_client.script_load = AsyncMock(return_value="valid_sha")
    mock_client.evalsha = AsyncMock(return_value=1)

    redis_dedup = RedisDeduplicator(client=mock_client)
    mem_dedup = InMemoryDeduplicator()
    metrics = DeduplicationMetrics()
    service = DeduplicationService(
        redis_deduplicator=redis_dedup,
        memory_deduplicator=mem_dedup,
        metrics=metrics,
    )

    res = await service.evaluate("tenant-up", "fp-redis")
    assert not res.is_duplicate
    assert res.storage_backend == DeduplicationBackendEnum.REDIS
    assert metrics.get_snapshot().redis_hits == 1


# ==============================================================================
# 4. Global Toggle & Synchronous Service Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_deduplication_disabled_toggle() -> None:
    """When enabled=False, all evaluations return novel without suppressing."""
    service = DeduplicationService(redis_deduplicator=RedisDeduplicator(redis_url=""))
    config = DeduplicationConfig(enabled=False)

    res1 = await service.evaluate("t1", "fp-same", config=config)
    res2 = await service.evaluate("t1", "fp-same", config=config)

    assert not res1.is_duplicate
    assert not res2.is_duplicate
    assert res1.duplicate_count == 1
    assert res2.duplicate_count == 1


def test_service_evaluate_sync() -> None:
    """Synchronous evaluate_sync utilizes in-memory fallback smoothly."""
    service = DeduplicationService(redis_deduplicator=RedisDeduplicator(redis_url=""))
    res1 = service.evaluate_sync("tenant-s", "fp-s")
    assert not res1.is_duplicate
    assert res1.duplicate_count == 1

    res2 = service.evaluate_sync("tenant-s", "fp-s")
    assert res2.is_duplicate
    assert res2.duplicate_count == 2


# ==============================================================================
# 5. ParsedResult Pipeline Adapter Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_deduplicate_parsed_result_attributes_injection() -> None:
    """deduplicate_parsed_result injects duplicate metadata without mutating original."""
    raw_result = ParsedResult(
        success=True,
        format=LogFormatEnum.CEF,
        parsed_by=ParsingTierEnum.RULE,
        confidence=1.0,
        raw_timestamp="2026-10-30T10:00:00Z",
        severity=SeverityEnum.ERROR,
        action="BLOCK",
        source=SourceInfo(ip="192.168.1.10", port=1234),
        destination=DestinationInfo(ip="10.0.0.1", port=443),
        attributes={"tenant": "sec-corp", "message": "Malicious traffic detected"},
    )

    mem = InMemoryDeduplicator()
    service = DeduplicationService(
        redis_deduplicator=RedisDeduplicator(redis_url=""),
        memory_deduplicator=mem,
    )

    # First encounter
    parsed_1, dedup_1 = await deduplicate_parsed_result(
        result=raw_result,
        tenant_id="sec-corp",
        service=service,
    )
    assert not dedup_1.is_duplicate
    assert dedup_1.duplicate_count == 1
    assert parsed_1.attributes["is_duplicate"] is False
    assert parsed_1.attributes["duplicate_count"] == 1
    assert "event_fingerprint" in parsed_1.attributes
    assert "is_duplicate" not in raw_result.attributes  # Original immutability preserved

    # Second encounter of identical log
    parsed_2, dedup_2 = await deduplicate_parsed_result(
        result=raw_result,
        tenant_id="sec-corp",
        service=service,
    )
    assert dedup_2.is_duplicate is True
    assert dedup_2.duplicate_count == 2
    assert parsed_2.attributes["is_duplicate"] is True
    assert parsed_2.attributes["duplicate_count"] == 2
    assert parsed_2.attributes["event_fingerprint"] == parsed_1.attributes["event_fingerprint"]


# ==============================================================================
# 6. Telemetry Metrics Audit & Reconciliation
# ==============================================================================


def test_telemetry_metrics_audit() -> None:
    """Verify metrics calculation and reconciliation formula."""
    metrics = DeduplicationMetrics()
    metrics.record_evaluation(is_duplicate=False, backend=DeduplicationBackendEnum.REDIS)
    metrics.record_evaluation(is_duplicate=True, backend=DeduplicationBackendEnum.REDIS)
    metrics.record_evaluation(is_duplicate=True, backend=DeduplicationBackendEnum.MEMORY_FALLBACK)
    metrics.record_evaluation(is_duplicate=False, backend=DeduplicationBackendEnum.MEMORY_FALLBACK)

    snap = metrics.get_snapshot()
    assert snap.total_evaluated == 4
    assert snap.unique_events == 2
    assert snap.duplicates_suppressed == 2
    assert snap.suppression_rate_pct == 50.0
    assert snap.redis_hits == 2
    assert snap.memory_fallback_hits == 2

    # Reconciliation invariant
    assert snap.total_evaluated == snap.unique_events + snap.duplicates_suppressed
    assert snap.total_evaluated == snap.redis_hits + snap.memory_fallback_hits

    # Reset
    metrics.reset()
    assert metrics.get_snapshot().total_evaluated == 0


# ==============================================================================
# 7. Edge Cases & Resilience Tests
# ==============================================================================


def test_fingerprint_unicode_multilingual() -> None:
    """Fingerprint handles non-ASCII UTF-8 characters and symbols cleanly."""
    fp1 = compute_event_fingerprint(
        tenant_id="tenant-jp",
        message="エラー発生: データベース接続失敗 ⚠️",
    )
    fp2 = compute_event_fingerprint(
        tenant_id="tenant-jp",
        message="エラー発生: データベース接続失敗 ⚠️",
    )
    assert len(fp1) == 64
    assert fp1 == fp2


def test_fingerprint_sparse_fields() -> None:
    """Fingerprint with sparse/None fields computes deterministically without error."""
    fp = compute_event_fingerprint(tenant_id="tenant-sparse")
    assert len(fp) == 64


@pytest.mark.asyncio
async def test_in_memory_refresh_ttl_on_duplicate() -> None:
    """When refresh_ttl=True, duplicate observations extend the monotonic expiry."""
    mem = InMemoryDeduplicator()
    tenant = "tenant-refresh"
    fp = "refresh-test-fp"

    await mem.evaluate(tenant, fp, ttl_seconds=10, refresh_ttl=True)
    exp1, count1 = mem._cache[f"{tenant}:{fp}"]

    # Simulate 0.05s passage
    time.sleep(0.05)
    await mem.evaluate(tenant, fp, ttl_seconds=10, refresh_ttl=True)
    exp2, count2 = mem._cache[f"{tenant}:{fp}"]

    assert count2 == 2
    assert exp2 > exp1


def test_in_memory_clear() -> None:
    """Calling clear() purges all stored items."""
    mem = InMemoryDeduplicator()
    mem.evaluate_sync("t", "fp1")
    assert mem.size == 1
    mem.clear()
    assert mem.size == 0


@pytest.mark.asyncio
async def test_redis_deduplicator_noscript_reload_retry() -> None:
    """When Redis server throws NOSCRIPT, RedisDeduplicator reloads and retries."""
    mock_client = AsyncMock()
    mock_client.script_load = AsyncMock(return_value="reloaded_sha")
    # First call throws NOSCRIPT RedisError, second call succeeds with count 1
    mock_client.evalsha = AsyncMock(
        side_effect=[
            RedisConnectionError("NOSCRIPT No matching script. Please use EVAL."),
            1,
        ]
    )

    redis_dedup = RedisDeduplicator(client=mock_client)
    redis_dedup._lua_sha = "stale_sha"

    res = await redis_dedup.evaluate("tenant-retry", "fp-retry")
    assert res == (False, 1)
    assert mock_client.script_load.called


@pytest.mark.asyncio
async def test_service_close_lifecycle() -> None:
    """Closing DeduplicationService safely invokes Redis client close."""
    mock_client = AsyncMock()
    mock_client.aclose = AsyncMock()
    redis_dedup = RedisDeduplicator(client=mock_client)
    service = DeduplicationService(redis_deduplicator=redis_dedup)

    await service.close()
    assert mock_client.aclose.called



# ==============================================================================
# 7. Performance SLA Benchmark (< 50 microseconds / evaluation)
# ==============================================================================


def test_in_memory_deduplication_performance_sla() -> None:
    """1,000 evaluations must complete in under 50ms (average < 50us per log)."""
    mem = InMemoryDeduplicator()
    tenant = "sla-tenant"

    start = time.perf_counter()
    for i in range(1000):
        fp = f"sla-fingerprint-{i % 100}"  # 100 unique fingerprints repeated 10 times
        mem.evaluate_sync(tenant, fp, ttl_seconds=60)
    duration = time.perf_counter() - start

    avg_us = (duration / 1000.0) * 1_000_000.0
    assert duration < 0.05, f"Took {duration:.4f}s; expected < 0.05s"
    assert avg_us < 50.0, f"Average evaluation {avg_us:.2f}us; expected < 50us"
