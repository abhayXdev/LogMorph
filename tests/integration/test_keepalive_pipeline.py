"""Integration tests for keep-alive connection stability across heavy payloads (FIX-P13)."""

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.keys import generate_api_key
from logmorph.core.security import hash_password
from logmorph.db.models import ApiKey, User


async def _create_test_tenant(
    session: AsyncSession,
    email: str = "keepalive_tenant@logmorph.io",
    name: str = "Keepalive Tenant",
) -> tuple[User, str]:
    """Helper to create and persist a test tenant and API key."""
    user = User(
        email=email,
        full_name=name,
        hashed_password=hash_password("KeepalivePass#2026"),
        is_verified=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    key_data = generate_api_key()
    api_key = ApiKey(
        name=f"{name} Key",
        key_hash=key_data.key_hash,
        key_prefix=key_data.key_prefix,
        user_id=user.id,
    )
    session.add(api_key)
    await session.commit()

    return user, key_data.raw_key


@pytest.mark.asyncio
async def test_keepalive_sequential_requests_survive_large_payload(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify persistent client connection survives heavy payloads without reset (FIX-P13)."""
    _, raw_key = await _create_test_tenant(async_db)
    headers = {"X-API-Key": raw_key}

    # Request 1: Normal baseline ingest
    resp1 = await async_client.post(
        "/api/v1/ingest",
        json={"raw_log": "<34>1 2026-11-22T12:00:00.000Z myhost app 1234 - - Normal log message 1"},
        headers=headers,
    )
    assert resp1.status_code == 202
    assert "event_id" in resp1.json()

    # Request 2: Heavy payload on the same persistent socket (7 KB string)
    heavy_log = "X" * 7000
    resp2 = await async_client.post(
        "/api/v1/ingest",
        json={"raw_log": heavy_log},
        headers=headers,
    )
    assert resp2.status_code == 202
    assert "event_id" in resp2.json()

    # Request 3: Follow-up request on the SAME persistent connection
    # Prior to FIX-P13, Uvicorn's 5s keep-alive caused ConnectionResetError here
    resp3 = await async_client.post(
        "/api/v1/ingest",
        json={"raw_log": "<34>1 2026-11-22T12:00:01.000Z myhost app 1235 - - Normal log after heavy payload"},
        headers=headers,
    )
    assert resp3.status_code == 202
    assert "event_id" in resp3.json()

    # Request 4: Health check on the same connection
    resp4 = await async_client.get("/health")
    assert resp4.status_code == 200
    assert resp4.json()["status"] in ("healthy", "degraded")


@pytest.mark.asyncio
async def test_keepalive_pipeline_rapid_pipelined_requests(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify client can pipeline multiple requests through the same HTTP connection."""
    _, raw_key = await _create_test_tenant(async_db, email="pipelined@logmorph.io")
    headers = {"X-API-Key": raw_key}

    for i in range(10):
        resp = await async_client.post(
            "/api/v1/ingest",
            json={"raw_log": f"Pipelined log event #{i}"},
            headers=headers,
        )
        assert resp.status_code == 202
        assert "event_id" in resp.json()
