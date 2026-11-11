"""Tenant-aware sliding-window log deduplication service.

Provides deterministic cryptographic SHA-256 event fingerprinting,
multi-tenant isolated Redis key partitioning, atomic sliding-window Lua execution,
and an autonomous in-memory LRU/TTL fallback cache.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
import time
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from logmorph.config import settings
from logmorph.engine.parsers.base import ParsedResult
from logmorph.schemas.deduplication import (
    DeduplicationBackendEnum,
    DeduplicationConfig,
    DeduplicationMetricsSnapshot,
    DeduplicationResult,
)

logger = logging.getLogger(__name__)

# Atomic Redis Lua script: increments counter and sets TTL on first observation.
# Optionally refreshes TTL on duplicate if refresh == 1.
_DEDUP_LUA_SCRIPT = """
local key = KEYS[1]
local ttl = tonumber(ARGV[1])
local refresh = tonumber(ARGV[2])
local current = redis.call('INCR', key)
if current == 1 then
    redis.call('EXPIRE', key, ttl)
elseif refresh == 1 then
    redis.call('EXPIRE', key, ttl)
end
return current
"""


def compute_event_fingerprint(
    tenant_id: str,
    timestamp_str: str | None = None,
    source_ip: str | None = None,
    source_port: int | str | None = None,
    destination_ip: str | None = None,
    destination_port: int | str | None = None,
    action: str | None = None,
    message: str | None = None,
) -> str:
    """Compute a deterministic, collision-resistant SHA-256 event fingerprint.

    Uses an ASCII unit separator (0x1F) to delineate canonical fields, preventing
    boundary injection vulnerabilities while preserving strict tenant isolation.
    """
    components = [
        (tenant_id or "").strip(),
        (timestamp_str or "").strip(),
        (source_ip or "").strip(),
        str(source_port).strip() if source_port is not None else "",
        (destination_ip or "").strip(),
        str(destination_port).strip() if destination_port is not None else "",
        (action or "").strip().upper(),
        (message or "").strip(),
    ]
    payload = "\x1f".join(components)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class InMemoryDeduplicator:
    """Bounded, thread-safe in-memory sliding-window deduplicator.

    Acts as an autonomous zero-downtime fallback whenever Redis is unreachable
    or unconfigured.
    """

    def __init__(self, max_entries: int = 50000) -> None:
        self._max_entries = max_entries
        self._cache: dict[str, tuple[float, int]] = {}
        self._lock = asyncio.Lock()
        self._sync_lock = threading.Lock()

    def _evaluate_entry(
        self,
        key: str,
        ttl_seconds: int,
        refresh_ttl: bool,
    ) -> tuple[bool, int]:
        now = time.monotonic()

        if key in self._cache:
            expiry, count = self._cache[key]
            if now < expiry:
                new_count = count + 1
                new_expiry = (now + ttl_seconds) if refresh_ttl else expiry
                self._cache[key] = (new_expiry, new_count)
                return True, new_count
            # Expired entry, treat as novel
            self._cache[key] = (now + ttl_seconds, 1)
            return False, 1

        # Enforce capacity bound before inserting a new key
        if len(self._cache) >= self._max_entries:
            # Step 1: Prune expired keys
            expired = [k for k, (exp, _) in self._cache.items() if now >= exp]
            for exp_key in expired:
                del self._cache[exp_key]

            # Step 2: If still at capacity, evict oldest 10% (FIFO via dict ordering)
            if len(self._cache) >= self._max_entries:
                evict_count = max(1, self._max_entries // 10)
                oldest_keys = list(self._cache.keys())[:evict_count]
                for old_key in oldest_keys:
                    del self._cache[old_key]

        self._cache[key] = (now + ttl_seconds, 1)
        return False, 1

    async def evaluate(
        self,
        tenant_id: str,
        fingerprint: str,
        ttl_seconds: int = 60,
        refresh_ttl: bool = False,
    ) -> tuple[bool, int]:
        """Evaluate event against in-memory sliding window asynchronously."""
        key = f"{tenant_id}:{fingerprint}"
        async with self._lock:
            return self._evaluate_entry(key, ttl_seconds, refresh_ttl)

    def evaluate_sync(
        self,
        tenant_id: str,
        fingerprint: str,
        ttl_seconds: int = 60,
        refresh_ttl: bool = False,
    ) -> tuple[bool, int]:
        """Synchronous evaluation for non-async execution paths."""
        key = f"{tenant_id}:{fingerprint}"
        with self._sync_lock:
            return self._evaluate_entry(key, ttl_seconds, refresh_ttl)

    def clear(self) -> None:
        """Purge all entries from the in-memory cache."""
        with self._sync_lock:
            self._cache.clear()

    @property
    def size(self) -> int:
        """Return the current number of active entries."""
        return len(self._cache)


class RedisDeduplicator:
    """Distributed sliding-window deduplicator backed by Redis.

    Uses an atomic Lua script to guarantee race-condition-free counter
    increments and TTL window expiration across distributed workers.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        client: aioredis.Redis | None = None,
    ) -> None:
        self._redis_url = redis_url or settings.REDIS_URL
        self._client: aioredis.Redis | None = client
        self._lua_sha: str | None = None
        self._lock = asyncio.Lock()

    async def get_client(self) -> aioredis.Redis | None:
        """Lazily initialize and return the async Redis connection."""
        if self._client is not None:
            return self._client

        if not self._redis_url:
            return None

        async with self._lock:
            if self._client is None:
                try:
                    self._client = aioredis.from_url(
                        self._redis_url,
                        decode_responses=True,
                        socket_timeout=1.0,
                        socket_connect_timeout=1.0,
                    )
                except Exception as exc:
                    logger.warning("Failed to initialize Redis client: %s", exc)
                    return None
            return self._client

    async def evaluate(
        self,
        tenant_id: str,
        fingerprint: str,
        ttl_seconds: int = 60,
        refresh_ttl: bool = False,
    ) -> tuple[bool, int] | None:
        """Evaluate duplicate status using atomic Lua script.

        Returns (is_duplicate, duplicate_count) or None if Redis is unreachable.
        """
        client = await self.get_client()
        if client is None:
            return None

        key = f"logmorph:dedup:{tenant_id}:{fingerprint}"
        refresh_flag = 1 if refresh_ttl else 0

        try:
            # Register or execute cached Lua script
            if self._lua_sha is None:
                self._lua_sha = await client.script_load(_DEDUP_LUA_SCRIPT)

            current = await client.evalsha(
                self._lua_sha,
                1,
                key,
                str(ttl_seconds),
                str(refresh_flag),
            )
            count = int(current)
            return (count > 1), count
        except RedisError as redis_err:
            # In case script cache was flushed on Redis server (NOSCRIPT error)
            if "NOSCRIPT" in str(redis_err):
                try:
                    self._lua_sha = await client.script_load(_DEDUP_LUA_SCRIPT)
                    current = await client.evalsha(
                        self._lua_sha,
                        1,
                        key,
                        str(ttl_seconds),
                        str(refresh_flag),
                    )
                    count = int(current)
                    return (count > 1), count
                except Exception as retry_exc:
                    logger.warning("Redis Lua retry failed: %s", retry_exc)
                    return None
            logger.warning("Redis deduplication evaluation failed: %s", redis_err)
            return None
        except Exception as exc:
            logger.warning("Unexpected error during Redis deduplication: %s", exc)
            return None

    async def close(self) -> None:
        """Gracefully close the Redis connection pool."""
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception as exc:
                logger.debug("Error closing Redis client: %s", exc)
            finally:
                self._client = None
                self._lua_sha = None


class DeduplicationMetrics:
    """Thread-safe telemetry collector for deduplication auditability."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total_evaluated: int = 0
        self._unique_events: int = 0
        self._duplicates_suppressed: int = 0
        self._redis_hits: int = 0
        self._memory_fallback_hits: int = 0

    def record_evaluation(
        self,
        is_duplicate: bool,
        backend: DeduplicationBackendEnum,
    ) -> None:
        """Record the outcome of a deduplication evaluation."""
        with self._lock:
            self._total_evaluated += 1
            if is_duplicate:
                self._duplicates_suppressed += 1
            else:
                self._unique_events += 1

            if backend == DeduplicationBackendEnum.REDIS:
                self._redis_hits += 1
            else:
                self._memory_fallback_hits += 1

    def get_snapshot(self) -> DeduplicationMetricsSnapshot:
        """Produce an immutable point-in-time metrics snapshot."""
        with self._lock:
            rate = (
                (self._duplicates_suppressed / self._total_evaluated * 100.0)
                if self._total_evaluated > 0
                else 0.0
            )
            return DeduplicationMetricsSnapshot(
                total_evaluated=self._total_evaluated,
                unique_events=self._unique_events,
                duplicates_suppressed=self._duplicates_suppressed,
                suppression_rate_pct=round(rate, 2),
                redis_hits=self._redis_hits,
                memory_fallback_hits=self._memory_fallback_hits,
            )

    def reset(self) -> None:
        """Reset all metrics counters to zero."""
        with self._lock:
            self._total_evaluated = 0
            self._unique_events = 0
            self._duplicates_suppressed = 0
            self._redis_hits = 0
            self._memory_fallback_hits = 0


# Global metrics collector instance
dedup_metrics = DeduplicationMetrics()


class DeduplicationService:
    """Unified deduplication service coordinating Redis primary and in-memory fallback."""

    def __init__(
        self,
        redis_deduplicator: RedisDeduplicator | None = None,
        memory_deduplicator: InMemoryDeduplicator | None = None,
        metrics: DeduplicationMetrics | None = None,
    ) -> None:
        self._redis = redis_deduplicator or RedisDeduplicator()
        self._memory = memory_deduplicator or InMemoryDeduplicator()
        self._metrics = metrics or dedup_metrics

    async def evaluate(
        self,
        tenant_id: str,
        fingerprint: str,
        config: DeduplicationConfig | None = None,
    ) -> DeduplicationResult:
        """Evaluate deduplication status across storage tiers.

        Attempts Redis atomic evaluation first; seamlessly falls back to
        the bounded in-memory sliding window if Redis is offline or disabled.
        """
        cfg = config or DeduplicationConfig()

        if not cfg.enabled:
            return DeduplicationResult(
                is_duplicate=False,
                duplicate_count=1,
                fingerprint=fingerprint,
                tenant_id=tenant_id,
                ttl_seconds=cfg.ttl_seconds,
                storage_backend=DeduplicationBackendEnum.MEMORY_FALLBACK,
            )

        # Tier 1: Distributed Redis Sliding Window
        redis_result = await self._redis.evaluate(
            tenant_id=tenant_id,
            fingerprint=fingerprint,
            ttl_seconds=cfg.ttl_seconds,
            refresh_ttl=cfg.refresh_ttl_on_duplicate,
        )

        if redis_result is not None:
            is_dup, count = redis_result
            backend = DeduplicationBackendEnum.REDIS
        else:
            # Tier 2: Resilient In-Memory Sliding-Window Fallback
            is_dup, count = await self._memory.evaluate(
                tenant_id=tenant_id,
                fingerprint=fingerprint,
                ttl_seconds=cfg.ttl_seconds,
                refresh_ttl=cfg.refresh_ttl_on_duplicate,
            )
            backend = DeduplicationBackendEnum.MEMORY_FALLBACK

        self._metrics.record_evaluation(is_duplicate=is_dup, backend=backend)

        return DeduplicationResult(
            is_duplicate=is_dup,
            duplicate_count=count,
            fingerprint=fingerprint,
            tenant_id=tenant_id,
            ttl_seconds=cfg.ttl_seconds,
            storage_backend=backend,
        )

    def evaluate_sync(
        self,
        tenant_id: str,
        fingerprint: str,
        config: DeduplicationConfig | None = None,
    ) -> DeduplicationResult:
        """Synchronous evaluation utilizing the in-memory fallback engine directly."""
        cfg = config or DeduplicationConfig()

        if not cfg.enabled:
            return DeduplicationResult(
                is_duplicate=False,
                duplicate_count=1,
                fingerprint=fingerprint,
                tenant_id=tenant_id,
                ttl_seconds=cfg.ttl_seconds,
                storage_backend=DeduplicationBackendEnum.MEMORY_FALLBACK,
            )

        is_dup, count = self._memory.evaluate_sync(
            tenant_id=tenant_id,
            fingerprint=fingerprint,
            ttl_seconds=cfg.ttl_seconds,
            refresh_ttl=cfg.refresh_ttl_on_duplicate,
        )
        backend = DeduplicationBackendEnum.MEMORY_FALLBACK
        self._metrics.record_evaluation(is_duplicate=is_dup, backend=backend)

        return DeduplicationResult(
            is_duplicate=is_dup,
            duplicate_count=count,
            fingerprint=fingerprint,
            tenant_id=tenant_id,
            ttl_seconds=cfg.ttl_seconds,
            storage_backend=backend,
        )

    async def close(self) -> None:
        """Close connection handles."""
        await self._redis.close()

    @property
    def metrics(self) -> DeduplicationMetrics:
        """Access the telemetry collector."""
        return self._metrics

    @property
    def memory_deduplicator(self) -> InMemoryDeduplicator:
        """Access the underlying in-memory cache."""
        return self._memory


# Default singleton instance
default_deduplication_service = DeduplicationService()


async def deduplicate_parsed_result(
    result: ParsedResult,
    tenant_id: str,
    config: DeduplicationConfig | None = None,
    service: DeduplicationService | None = None,
) -> tuple[ParsedResult, DeduplicationResult]:
    """Evaluate duplicate state of a ParsedResult and inject deduplication attributes.

    Returns a new immutable ParsedResult containing the deduplication metadata
    (`is_duplicate`, `duplicate_count`, `event_fingerprint`) along with the
    underlying DeduplicationResult.
    """
    svc = service or default_deduplication_service
    cfg = config or DeduplicationConfig()

    timestamp_str = (
        result.attributes.get("timestamp_normalized")
        or result.raw_timestamp
        or ""
    )
    source_ip = result.source.ip if result.source else None
    source_port = result.source.port if result.source else None
    dest_ip = result.destination.ip if result.destination else None
    dest_port = result.destination.port if result.destination else None
    action = result.action
    message = (
        result.attributes.get("message")
        or result.attributes.get("raw_log")
        or result.error_message
        or ""
    )

    fingerprint = compute_event_fingerprint(
        tenant_id=tenant_id,
        timestamp_str=timestamp_str,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=dest_ip,
        destination_port=dest_port,
        action=action,
        message=message,
    )

    dedup_result = await svc.evaluate(
        tenant_id=tenant_id,
        fingerprint=fingerprint,
        config=cfg,
    )

    updated_attributes: dict[str, Any] = {
        **result.attributes,
        "is_duplicate": dedup_result.is_duplicate,
        "duplicate_count": dedup_result.duplicate_count,
        "event_fingerprint": dedup_result.fingerprint,
        "dedup_backend": dedup_result.storage_backend.value,
    }

    cloned_result = result.model_copy(
        update={"attributes": updated_attributes},
    )

    return cloned_result, dedup_result
