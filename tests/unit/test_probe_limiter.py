"""Unit tests for adaptive 404 cascade rate limiter (FIX-P15)."""

import time
import uuid

import pytest

from logmorph.core.exceptions import TooManyProbesException
from logmorph.core.probe_limiter import (
    MAX_404_PROBES_PER_WINDOW,
    _memory_probe_history,
    record_404_and_check_limit,
    reset_probe_limiter,
)


@pytest.fixture(autouse=True)
def clean_probe_limiter():
    """Reset probe limiter before and after each test."""
    reset_probe_limiter()
    yield
    reset_probe_limiter()


@pytest.mark.asyncio
async def test_probe_limiter_under_threshold():
    """Verify that 404 probes up to the threshold increment count without error."""
    tenant_id = uuid.uuid4()
    for expected_count in range(1, 6):
        count = await record_404_and_check_limit(tenant_id, max_probes=5, window_seconds=60)
        assert count == expected_count


@pytest.mark.asyncio
async def test_probe_limiter_exceeds_threshold_raises_429():
    """Verify exceeding max_probes raises TooManyProbesException with 429 and Retry-After header."""
    tenant_id = uuid.uuid4()
    for _ in range(5):
        await record_404_and_check_limit(tenant_id, max_probes=5, window_seconds=60)

    with pytest.raises(TooManyProbesException) as exc_info:
        await record_404_and_check_limit(tenant_id, max_probes=5, window_seconds=60)

    exc = exc_info.value
    assert exc.status_code == 429
    assert exc.error_code == "TOO_MANY_404_PROBES"
    assert "Too many not-found requests" in exc.detail
    assert exc.headers.get("Retry-After") == "60"


@pytest.mark.asyncio
async def test_probe_limiter_tenant_isolation():
    """Verify probe counters are strictly partitioned by tenant ID."""
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    for _ in range(5):
        await record_404_and_check_limit(tenant_a, max_probes=5, window_seconds=60)

    # Tenant A is now throttled
    with pytest.raises(TooManyProbesException):
        await record_404_and_check_limit(tenant_a, max_probes=5, window_seconds=60)

    # Tenant B is fresh and should not be throttled
    count_b = await record_404_and_check_limit(tenant_b, max_probes=5, window_seconds=60)
    assert count_b == 1


@pytest.mark.asyncio
async def test_probe_limiter_sliding_window_expiration(monkeypatch: pytest.MonkeyPatch):
    """Verify expired timestamps outside the sliding window are pruned."""
    tenant_id = str(uuid.uuid4())
    fake_time = 1000.0

    monkeypatch.setattr(time, "monotonic", lambda: fake_time)

    # Record 3 probes at t=1000.0
    for _ in range(3):
        await record_404_and_check_limit(tenant_id, max_probes=5, window_seconds=60)

    assert len(_memory_probe_history[tenant_id]) == 3

    # Advance time by 61 seconds (past window)
    monkeypatch.setattr(time, "monotonic", lambda: fake_time + 61.0)

    # Next probe should prune all 3 expired timestamps and return count=1
    count = await record_404_and_check_limit(tenant_id, max_probes=5, window_seconds=60)
    assert count == 1
    assert len(_memory_probe_history[tenant_id]) == 1


def test_default_constants():
    """Verify production default limits are calibrated correctly."""
    assert MAX_404_PROBES_PER_WINDOW == 20
