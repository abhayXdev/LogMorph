"""Centralized rate limiting provider using slowapi with Redis and Memory storage fallback."""

from __future__ import annotations

import logging

from fastapi import Request
from slowapi import Limiter

from logmorph.config import settings

logger = logging.getLogger(__name__)


def get_client_ip(request: Request) -> str:
    """Extract real client IP address supporting X-Forwarded-For behind reverse proxies."""
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def _get_storage_uri() -> str:
    """Determine the optimal storage URI for the slowapi rate limiter.

    Uses Redis if configured and reachable; otherwise falls back to memory://
    so that unit tests and development run with zero external infrastructure.
    """
    if settings.ENVIRONMENT in ("test", "development"):
        return "memory://"

    if settings.REDIS_URL:
        try:
            import redis

            r = redis.from_url(settings.REDIS_URL, socket_timeout=1)
            r.ping()
            r.close()
            logger.info("Rate limiter initialized with Redis storage: %s", settings.REDIS_URL)
            return settings.REDIS_URL
        except Exception as e:
            logger.warning(
                "Redis unreachable for rate limiter (%s). Falling back to in-memory storage.",
                e,
            )

    return "memory://"


limiter = Limiter(
    key_func=get_client_ip,
    storage_uri=_get_storage_uri(),
    default_limits=[],
)
