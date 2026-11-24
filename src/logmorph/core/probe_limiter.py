"""Adaptive 404 cascade rate limiter per tenant (FIX-P15).

Throttles rapid UUID enumeration and IDOR brute-force probes.
Tracks the number of 404 Not Found responses each authenticated tenant triggers
within a sliding 60-second window. If a tenant exceeds 20 404s per minute,
subsequent 404 responses are escalated to HTTP 429 Too Many Requests.
"""

from __future__ import annotations

import logging
import time
from uuid import UUID

from logmorph.config import settings
from logmorph.core.exceptions import TooManyProbesException

logger = logging.getLogger(__name__)

MAX_404_PROBES_PER_WINDOW: int = 20
PROBE_WINDOW_SECONDS: int = 60

# In-memory sliding window storage: {tenant_id: [timestamp, ...]}
_memory_probe_history: dict[str, list[float]] = {}


def reset_probe_limiter() -> None:
    """Reset in-memory probe history (primarily used for deterministic test runs)."""
    _memory_probe_history.clear()


def _record_memory_probe(tenant_key: str, window_seconds: int = PROBE_WINDOW_SECONDS) -> int:
    """Record a 404 occurrence in the in-memory sliding window and return active count."""
    now = time.monotonic()
    cutoff = now - window_seconds
    timestamps = _memory_probe_history.get(tenant_key, [])
    # Prune expired timestamps
    active = [t for t in timestamps if t > cutoff]
    active.append(now)
    _memory_probe_history[tenant_key] = active
    return len(active)


async def _record_redis_probe(tenant_key: str, window_seconds: int = PROBE_WINDOW_SECONDS) -> int:
    """Record a 404 occurrence in Redis using atomic INCR + EXPIRE."""
    import redis.asyncio as aioredis

    r_client = aioredis.from_url(settings.REDIS_URL, socket_timeout=1)
    try:
        redis_key = f"404_probe:{tenant_key}"
        count = await r_client.incr(redis_key)
        if count == 1:
            await r_client.expire(redis_key, window_seconds)
        return int(count)
    finally:
        await r_client.aclose()


async def record_404_and_check_limit(
    tenant_id: str | UUID,
    max_probes: int = MAX_404_PROBES_PER_WINDOW,
    window_seconds: int = PROBE_WINDOW_SECONDS,
) -> int:
    """Record a 404 occurrence for the tenant and raise 429 if the threshold is exceeded.

    Args:
        tenant_id: Authenticated tenant UUID or identifier.
        max_probes: Maximum allowed 404 probes within window (default 20).
        window_seconds: Window duration in seconds (default 60).

    Returns:
        The current count of 404 probes in the active window.

    Raises:
        TooManyProbesException: If count > max_probes (HTTP 429).
    """
    tenant_key = str(tenant_id)
    count: int

    # In test and development environments, or when Redis is unconfigured, use in-memory window
    if settings.ENVIRONMENT in ("test", "development") or not settings.REDIS_URL:
        count = _record_memory_probe(tenant_key, window_seconds)
    else:
        try:
            count = await _record_redis_probe(tenant_key, window_seconds)
        except Exception as exc:
            logger.warning("Redis 404 rate limit tracking failed (%s); falling back to memory.", exc)
            count = _record_memory_probe(tenant_key, window_seconds)

    if count > max_probes:
        logger.warning(
            "SECURITY: 404 probe rate limit exceeded for tenant %s (count=%d/%d). Throttling with HTTP 429.",
            tenant_key,
            count,
            max_probes,
            extra={
                "event_type": "404_CASCADE_RATE_LIMIT",
                "tenant_id": tenant_key,
                "probe_count": count,
                "threshold": max_probes,
            },
        )
        raise TooManyProbesException(
            detail="Too many not-found requests. Try again in 60 seconds.",
            error_code="TOO_MANY_404_PROBES",
            retry_after=window_seconds,
        )

    return count
