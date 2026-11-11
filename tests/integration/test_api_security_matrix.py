"""Security Matrix and Cross-Tenant Boundary Integration Tests.

Validates:
1. 401 Unauthorized gateway enforcement across all protected endpoints.
2. Malformed, expired, and revoked credentials rejection.
3. Cross-Tenant IDOR / BOLA attack prevention (Keys, Sources, Events).
4. SQL injection and payload sanitization parameterization safety.
5. Standardized 422 validation envelopes on malformed inputs.
"""

from datetime import UTC, datetime, timedelta
import uuid

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.keys import generate_api_key
from logmorph.core.security import create_access_token, hash_password
from logmorph.db.models import ApiKey, LogRecord, LogSource, User


async def _create_test_user(
    session: AsyncSession,
    email: str,
    full_name: str = "Test User",
) -> tuple[User, str]:
    """Helper to create verified user with valid JWT token."""
    user = User(
        email=email,
        full_name=full_name,
        hashed_password=hash_password("ComplexPass#2026"),
        is_verified=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    token = create_access_token(subject=user.id, email=user.email)
    return user, token


# ==============================================================================
# 1. Authentication Gateway Tests (401 Unauthorized)
# ==============================================================================


@pytest.mark.asyncio
async def test_protected_routes_unauthenticated_reject_401(async_client: AsyncClient):
    """Verify all protected API routes reject unauthenticated requests with 401."""
    protected_endpoints = [
        ("GET", "/auth/me"),
        ("POST", "/auth/change-password"),
        ("GET", "/api/v1/events"),
        ("GET", "/api/v1/events/search?q=test"),
        ("GET", f"/api/v1/events/evt_{uuid.uuid4()}"),
        ("DELETE", f"/api/v1/events/evt_{uuid.uuid4()}"),
        ("GET", "/api/v1/keys"),
        ("POST", "/api/v1/keys"),
        ("DELETE", f"/api/v1/keys/{uuid.uuid4()}"),
        ("GET", "/api/v1/sources"),
        ("POST", "/api/v1/sources"),
        ("DELETE", f"/api/v1/sources/{uuid.uuid4()}"),
        ("GET", "/api/v1/stats/overview"),
        ("GET", "/api/v1/stats/timeline"),
        ("GET", "/api/v1/stats/formats"),
        ("GET", "/api/v1/stats/severity"),
        ("GET", "/api/v1/stats/threats"),
        ("GET", "/api/v1/stats/cascade"),
    ]

    for method, path in protected_endpoints:
        if method == "GET":
            resp = await async_client.get(path)
        elif method == "POST":
            resp = await async_client.post(path, json={})
        elif method == "DELETE":
            resp = await async_client.delete(path)
        else:
            continue

        assert resp.status_code == 401, f"Endpoint {method} {path} expected 401, got {resp.status_code}"
        data = resp.json()
        assert "detail" in data
        assert data.get("error_code") == "UNAUTHORIZED" or "Not authenticated" in data["detail"]


@pytest.mark.asyncio
async def test_invalid_and_expired_jwt_tokens(async_client: AsyncClient):
    """Verify expired or malformed JWT tokens are rejected with 401."""
    # Malformed token
    bad_headers = {"Authorization": "Bearer not-a-valid-jwt-token"}
    resp = await async_client.get("/auth/me", headers=bad_headers)
    assert resp.status_code == 401

    # Expired token
    expired_token = create_access_token(
        subject="00000000-0000-0000-0000-000000000001",
        email="expired@corp.com",
        expires_delta=timedelta(seconds=-60),
    )
    exp_headers = {"Authorization": f"Bearer {expired_token}"}
    resp = await async_client.get("/auth/me", headers=exp_headers)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_ingest_endpoint_invalid_or_revoked_api_key(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify ingest endpoint rejects invalid or deactivated API keys with 401."""
    # Ingest without any key
    resp = await async_client.post("/api/v1/ingest", json={"raw_log": "test log"})
    assert resp.status_code == 401

    # Ingest with random fake key
    resp = await async_client.post(
        "/api/v1/ingest",
        headers={"X-API-Key": "lm_live_fakekey000000000000000000000000"},
        json={"raw_log": "test log"},
    )
    assert resp.status_code == 401

    # Ingest with deactivated / revoked key
    user, _ = await _create_test_user(async_db, "revoked_user@corp.com")
    key_info = generate_api_key()
    revoked_key = ApiKey(
        name="Revoked Ingest Key",
        key_hash=key_info.key_hash,
        key_prefix=key_info.key_prefix,
        is_active=False,
        user_id=user.id,
    )
    async_db.add(revoked_key)
    await async_db.commit()

    resp = await async_client.post(
        "/api/v1/ingest",
        headers={"X-API-Key": key_info.raw_key},
        json={"raw_log": "test log"},
    )
    assert resp.status_code == 401


# ==============================================================================
# 2. Cross-Tenant IDOR / BOLA Prevention Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_cross_tenant_api_key_deletion_prevention(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify Tenant B cannot delete Tenant A's API key (returns 404 Not Found)."""
    user_a, token_a = await _create_test_user(async_db, "victim_key_a@corp.com")
    _, token_b = await _create_test_user(async_db, "attacker_key_b@corp.com")

    # Tenant A creates an API key
    key_info = generate_api_key()
    api_key = ApiKey(
        name="Tenant A Secret Key",
        key_hash=key_info.key_hash,
        key_prefix=key_info.key_prefix,
        is_active=True,
        user_id=user_a.id,
    )
    async_db.add(api_key)
    await async_db.commit()
    await async_db.refresh(api_key)

    # Tenant B tries to delete Tenant A's key
    resp = await async_client.delete(
        f"/api/v1/keys/{api_key.id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 404

    # Verify key is still present and active in DB
    key_in_db = await async_db.get(ApiKey, api_key.id)
    assert key_in_db is not None
    assert key_in_db.is_active is True


@pytest.mark.asyncio
async def test_cross_tenant_source_deletion_prevention(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify Tenant B cannot delete Tenant A's Log Source (returns 404 Not Found)."""
    user_a, _ = await _create_test_user(async_db, "victim_source_a@corp.com")
    _, token_b = await _create_test_user(async_db, "attacker_source_b@corp.com")

    # Tenant A creates a log source
    source = LogSource(
        name="Tenant A Core Router",
        source_type="syslog",
        tenant_id=user_a.id,
    )
    async_db.add(source)
    await async_db.commit()
    await async_db.refresh(source)

    # Tenant B tries to delete Tenant A's source
    resp = await async_client.delete(
        f"/api/v1/sources/{source.id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 404

    # Verify source still exists
    source_in_db = await async_db.get(LogSource, source.id)
    assert source_in_db is not None


@pytest.mark.asyncio
async def test_cross_tenant_event_deletion_prevention(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify Tenant B cannot delete Tenant A's stored log event (returns 404 Not Found)."""
    user_a, _ = await _create_test_user(async_db, "victim_event_a@corp.com")
    _, token_b = await _create_test_user(async_db, "attacker_event_b@corp.com")

    event_id = f"evt_tenant_a_{uuid.uuid4()}"
    record = LogRecord(
        event_id=event_id,
        tenant_id=user_a.id,
        timestamp=datetime.now(UTC),
        raw_log="Tenant A internal audit log",
        detected_format="json",
        severity="INFO",
    )
    async_db.add(record)
    await async_db.commit()

    # Tenant B tries to delete Tenant A's event
    resp = await async_client.delete(
        f"/api/v1/events/{event_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 404

    # Verify event still exists in DB
    event_in_db = await async_db.get(LogRecord, record.id)
    assert event_in_db is not None


# ==============================================================================
# 3. SQL Injection & Parameterization Safety Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_search_sql_injection_safety(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify search endpoints safely handle SQL injection payloads without throwing 500s."""
    _, token = await _create_test_user(async_db, "sqli_test@corp.com")
    headers = {"Authorization": f"Bearer {token}"}

    malicious_queries = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "UNION SELECT NULL, NULL, NULL --",
        "admin'--",
        "<script>alert('xss')</script>",
        "Robert'); DROP TABLE log_records;--",
    ]

    for q in malicious_queries:
        # Search via list endpoint
        resp_list = await async_client.get(
            f"/api/v1/events?q={q}",
            headers=headers,
        )
        assert resp_list.status_code == 200
        assert "events" in resp_list.json()

        # Search via full-text search endpoint
        resp_search = await async_client.get(
            f"/api/v1/events/search?q={q}",
            headers=headers,
        )
        assert resp_search.status_code == 200
        assert "results" in resp_search.json()


# ==============================================================================
# 4. Standardized 422 Validation Envelope Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_pydantic_validation_error_envelope(async_client: AsyncClient):
    """Verify malformed requests trigger 422 with standardized error envelope."""
    # Invalid email in signup
    resp = await async_client.post(
        "/auth/signup",
        json={"email": "not-an-email", "password": "123", "full_name": "Bad User"},
    )
    assert resp.status_code == 422
    data = resp.json()
    assert data["status_code"] == 422
    assert data["error_code"] == "VALIDATION_ERROR"
    assert "detail" in data
