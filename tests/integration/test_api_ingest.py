"""Integration tests for REST API Ingestion webhooks and health endpoints."""

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.keys import generate_api_key
from logmorph.core.security import hash_password
from logmorph.db.models import ApiKey, User


async def _create_test_tenant_and_key(
    session: AsyncSession,
    email: str = "collector@tenant.com",
    is_active: bool = True,
) -> tuple[User, str, ApiKey]:
    """Helper to create a test user and associated API key in the test database."""
    user = User(
        email=email,
        full_name="Collector Ingestion User",
        hashed_password=hash_password("CollectorPass#2026"),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    key_data = generate_api_key()
    api_key = ApiKey(
        name="Ingestion Test Key",
        key_hash=key_data.key_hash,
        key_prefix=key_data.key_prefix,
        is_active=is_active,
        user_id=user.id,
    )
    session.add(api_key)
    await session.commit()
    await session.refresh(api_key)

    return user, key_data.raw_key, api_key


@pytest.mark.asyncio
async def test_health_check_endpoint(async_client: AsyncClient):
    """Verify that GET /health returns 200 OK with expected system telemetry."""
    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["version"] == "0.1.0"
    assert "uptime_seconds" in data
    assert isinstance(data["uptime_seconds"], int)


@pytest.mark.asyncio
async def test_single_log_ingest_with_bearer_token(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify single log ingestion with Authorization: Bearer <key> returns 202."""
    _, raw_key, _ = await _create_test_tenant_and_key(async_db)

    payload = {
        "raw_log": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
        "source": "production-firewall",
    }
    headers = {"Authorization": f"Bearer {raw_key}"}

    response = await async_client.post("/api/v1/ingest", json=payload, headers=headers)
    assert response.status_code == 202

    data = response.json()
    assert data["status"] == "accepted"
    assert "event_id" in data
    assert data["event_id"].startswith("evt_")


@pytest.mark.asyncio
async def test_single_log_ingest_with_x_api_key_header(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify single log ingestion with X-API-Key header returns 202."""
    _, raw_key, _ = await _create_test_tenant_and_key(
        async_db, email="xkey_tenant@corp.com"
    )

    payload = {
        "raw_log": "CEF:0|Palo Alto|Firewall|9.1|100|TRAFFIC|5|src=10.0.0.1 dst=10.0.0.2 act=ALLOW",
        "source": "palo-alto",
    }
    headers = {"X-API-Key": raw_key}

    response = await async_client.post("/api/v1/ingest", json=payload, headers=headers)
    assert response.status_code == 202

    data = response.json()
    assert data["status"] == "accepted"
    assert data["event_id"].startswith("evt_")


@pytest.mark.asyncio
async def test_batch_log_ingest_success(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify batch log ingestion returns 202 with count and list of unique event IDs."""
    _, raw_key, _ = await _create_test_tenant_and_key(
        async_db, email="batch_tenant@corp.com"
    )

    payload = {
        "logs": [
            "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
            '{"timestamp": "2026-09-23T10:00:00Z", "level": "ERROR", "msg": "Timeout"}',
            "CEF:0|Palo Alto|Firewall|9.1|100|TRAFFIC|5|src=192.168.1.10 dst=10.0.0.5 act=ALLOW",
        ],
        "source": "mixed-collector",
    }
    headers = {"Authorization": f"Bearer {raw_key}"}

    response = await async_client.post("/api/v1/ingest/batch", json=payload, headers=headers)
    assert response.status_code == 202

    data = response.json()
    assert data["status"] == "accepted"
    assert data["count"] == 3
    assert len(data["event_ids"]) == 3
    for eid in data["event_ids"]:
        assert eid.startswith("evt_")
    # All event IDs in batch must be globally unique
    assert len(set(data["event_ids"])) == 3


@pytest.mark.asyncio
async def test_ingest_missing_auth_header_fails(async_client: AsyncClient):
    """Verify ingestion without authentication header returns 401."""
    payload = {"raw_log": "sample log message"}
    response = await async_client.post("/api/v1/ingest", json=payload)
    assert response.status_code == 401

    data = response.json()
    assert data["status_code"] == 401
    assert data["error_code"] == "INVALID_API_KEY"


@pytest.mark.asyncio
async def test_ingest_malformed_api_key_fails(async_client: AsyncClient):
    """Verify ingestion with malformed API key returns 401."""
    payload = {"raw_log": "sample log message"}
    headers = {"Authorization": "Bearer not-a-valid-lm-key"}

    response = await async_client.post("/api/v1/ingest", json=payload, headers=headers)
    assert response.status_code == 401

    data = response.json()
    assert data["status_code"] == 401
    assert data["error_code"] == "INVALID_API_KEY"
    assert data["detail"] == "Invalid or inactive API key"


@pytest.mark.asyncio
async def test_ingest_nonexistent_api_key_fails(async_client: AsyncClient):
    """Verify validly formatted but unregistered API key returns 401."""
    unregistered_key = generate_api_key().raw_key
    payload = {"raw_log": "sample log message"}
    headers = {"Authorization": f"Bearer {unregistered_key}"}

    response = await async_client.post("/api/v1/ingest", json=payload, headers=headers)
    assert response.status_code == 401

    data = response.json()
    assert data["status_code"] == 401
    assert data["error_code"] == "INVALID_API_KEY"


@pytest.mark.asyncio
async def test_ingest_revoked_api_key_fails(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify deactivated/revoked API key returns 401."""
    _, raw_key, _ = await _create_test_tenant_and_key(
        async_db, email="revoked@corp.com", is_active=False
    )

    payload = {"raw_log": "sample log message"}
    headers = {"Authorization": f"Bearer {raw_key}"}

    response = await async_client.post("/api/v1/ingest", json=payload, headers=headers)
    assert response.status_code == 401

    data = response.json()
    assert data["status_code"] == 401
    assert data["error_code"] == "INVALID_API_KEY"


@pytest.mark.asyncio
async def test_ingest_whitespace_payload_fails_validation(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify whitespace-only raw log triggers 422 validation error."""
    _, raw_key, _ = await _create_test_tenant_and_key(
        async_db, email="validator@corp.com"
    )

    payload = {"raw_log": "   \t\n   "}
    headers = {"Authorization": f"Bearer {raw_key}"}

    response = await async_client.post("/api/v1/ingest", json=payload, headers=headers)
    assert response.status_code == 422

    data = response.json()
    assert data["status_code"] == 422
    assert data["error_code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_batch_ingest_empty_batch_fails_validation(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify empty logs list in batch ingestion triggers 422 validation error."""
    _, raw_key, _ = await _create_test_tenant_and_key(
        async_db, email="empty_batch@corp.com"
    )

    payload: dict[str, object] = {"logs": []}
    headers = {"Authorization": f"Bearer {raw_key}"}

    response = await async_client.post("/api/v1/ingest/batch", json=payload, headers=headers)
    assert response.status_code == 422

    data = response.json()
    assert data["status_code"] == 422
    assert data["error_code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_api_key_last_used_at_updated_on_ingest(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify that successful ingestion updates the ApiKey.last_used_at timestamp."""
    _, raw_key, db_key = await _create_test_tenant_and_key(
        async_db, email="audit_tenant@corp.com"
    )
    assert db_key.last_used_at is None

    payload = {"raw_log": "Audit test log message"}
    headers = {"Authorization": f"Bearer {raw_key}"}

    response = await async_client.post("/api/v1/ingest", json=payload, headers=headers)
    assert response.status_code == 202

    await async_db.refresh(db_key)
    assert db_key.last_used_at is not None
