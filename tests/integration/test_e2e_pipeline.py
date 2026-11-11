"""End-to-End Pipeline Integration Tests for LogMorph SaaS.

Validates the full unified lifecycle across all system components:
Tenant Provisioning -> Email Verification -> API Key -> Log Source -> Ingestion ->
Engine Cascade Processing -> Hot Storage -> Search & Retrieval API -> Stats -> Tenant Isolation.
"""

from datetime import UTC, datetime, timedelta
import uuid

import pytest
from httpx import AsyncClient
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.email import get_email_service
from logmorph.db.models import User
from logmorph.domain.uls import LogFormatEnum
from logmorph.engine.core import LogMorphEngine
from logmorph.storage.adapter import get_storage_adapter


@pytest.mark.asyncio
async def test_full_e2e_tenant_lifecycle_ingest_to_search(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Test full journey from user signup to email verification, API key creation,

    source registration, log ingestion, engine cascade processing, hot storage persistence,
    and search API retrieval with enrichment audit.
    """
    email_service = get_email_service()
    email_service.sent_emails.clear()

    # 1. Tenant Signup
    signup_resp = await async_client.post(
        "/auth/signup",
        json={
            "email": "e2e_analyst@enterprise.com",
            "password": "SecurePassword#2026",
            "full_name": "E2E Test Analyst",
        },
    )
    assert signup_resp.status_code == 201
    signup_data = signup_resp.json()
    assert signup_data["is_verified"] is False

    # Extract verification token hash from DB to simulate user clicking link
    stmt = select(User).where(User.email == "e2e_analyst@enterprise.com")
    user = (await async_db.exec(stmt)).first()
    assert user is not None
    assert user.verification_token_hash is not None

    # Find the verification email sent
    assert len(email_service.sent_emails) == 1
    sent_email = email_service.sent_emails[0]
    token_str = sent_email["text"].split("token=")[1].split()[0].strip()

    # 2. Verify Email
    verify_resp = await async_client.post(
        "/auth/verify-email",
        json={"token": token_str},
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["email"] == "e2e_analyst@enterprise.com"

    # 3. Login to obtain JWT
    login_resp = await async_client.post(
        "/auth/login",
        json={
            "email": "e2e_analyst@enterprise.com",
            "password": "SecurePassword#2026",
        },
    )
    assert login_resp.status_code == 200
    jwt_token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {jwt_token}"}

    # 4. Generate an Ingestion API Key
    key_resp = await async_client.post(
        "/api/v1/keys",
        headers=auth_headers,
        json={"name": "E2E Production Collector Key"},
    )
    assert key_resp.status_code == 201
    key_data = key_resp.json()
    raw_api_key = key_data["key"]
    ingest_headers = {"X-API-Key": raw_api_key}

    # 5. Register a Log Source
    source_resp = await async_client.post(
        "/api/v1/sources",
        headers=auth_headers,
        json={
            "name": "edge-firewall-01",
            "source_type": "syslog",
            "description": "Primary edge firewall syslog receiver",
        },
    )
    assert source_resp.status_code == 201
    source_id = source_resp.json()["id"]

    # 6. Ingest raw log via Ingestion Webhook
    raw_syslog = (
        "<34>1 2026-10-30T12:00:00.000Z edge-firewall-01 sshd 1234 ID47 - "
        "Failed password for invalid user admin from 185.220.101.5 port 54321 ssh2"
    )
    ingest_resp = await async_client.post(
        "/api/v1/ingest",
        headers=ingest_headers,
        json={
            "raw_log": raw_syslog,
            "source": "edge-firewall-01",
        },
    )
    assert ingest_resp.status_code == 202
    event_id = ingest_resp.json()["event_id"]
    assert event_id.startswith("evt_")

    # 7. Process through LogMorphEngine and persist to Hot Storage
    engine = LogMorphEngine()
    proc_result = engine.process(
        raw_log=raw_syslog,
        tenant_id=user.id,
    )
    assert proc_result.success is True
    assert proc_result.event is not None
    # Pin event_id to the ingested event_id for tracking
    proc_result.event.event_id = event_id

    storage_adapter = get_storage_adapter()
    await storage_adapter.store_event(async_db, proc_result.event)

    # 8. Query via Events List API
    events_resp = await async_client.get(
        "/api/v1/events?q=Failed password",
        headers=auth_headers,
    )
    assert events_resp.status_code == 200
    events_data = events_resp.json()
    assert events_data["pagination"]["total"] >= 1
    retrieved_event = events_data["events"][0]
    assert retrieved_event["event_id"] == event_id
    assert retrieved_event["detected_format"].upper() == "SYSLOG"

    # Query via Full-Text Search API
    search_resp = await async_client.get(
        "/api/v1/events/search?q=admin",
        headers=auth_headers,
    )
    assert search_resp.status_code == 200
    search_data = search_resp.json()
    assert search_data["total"] >= 1
    assert search_data["results"][0]["event_id"] == event_id

    # 9. Retrieve by specific Event ID
    detail_resp = await async_client.get(
        f"/api/v1/events/{event_id}",
        headers=auth_headers,
    )
    assert detail_resp.status_code == 200
    assert detail_resp.json()["event_id"] == event_id

    # 10. Audit Overview Stats
    stats_resp = await async_client.get(
        "/api/v1/stats/overview",
        headers=auth_headers,
    )
    assert stats_resp.status_code == 200
    stats_data = stats_resp.json()
    assert stats_data["total_events"] >= 1


@pytest.mark.asyncio
async def test_e2e_cross_tenant_isolation_zero_leakage(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify that Tenant B cannot search, retrieve, or view stats of Tenant A's logs."""
    # Create Tenant A
    signup_a = await async_client.post(
        "/auth/signup",
        json={"email": "victim_a@corp.com", "password": "Password#123", "full_name": "Tenant A"},
    )
    user_a_id = signup_a.json()["id"]
    token_a = signup_a.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Create Tenant B
    signup_b = await async_client.post(
        "/auth/signup",
        json={"email": "attacker_b@corp.com", "password": "Password#123", "full_name": "Tenant B"},
    )
    token_b = signup_b.json()["access_token"]
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Ingest and store log belonging to Tenant A
    engine = LogMorphEngine()
    raw_log = '{"event": "confidential_security_incident", "severity": "CRITICAL"}'
    proc_res = engine.process(raw_log=raw_log, tenant_id=user_a_id)
    assert proc_res.success is True
    assert proc_res.event is not None
    secret_event_id = f"evt_{uuid.uuid4()}"
    proc_res.event.event_id = secret_event_id

    storage = get_storage_adapter()
    await storage.store_event(async_db, proc_res.event)

    # Tenant A searches: finds 1 event
    search_a = await async_client.get(
        "/api/v1/events?q=confidential",
        headers=headers_a,
    )
    assert search_a.status_code == 200
    assert search_a.json()["pagination"]["total"] == 1

    # Tenant B searches: finds 0 events
    search_b = await async_client.get(
        "/api/v1/events?q=confidential",
        headers=headers_b,
    )
    assert search_b.status_code == 200
    assert search_b.json()["pagination"]["total"] == 0

    # Tenant B attempts direct lookup of Tenant A's event_id -> 404
    detail_b = await async_client.get(
        f"/api/v1/events/{secret_event_id}",
        headers=headers_b,
    )
    assert detail_b.status_code == 404

    # Tenant B stats overview shows 0
    stats_b = await async_client.get(
        "/api/v1/stats/overview",
        headers=headers_b,
    )
    assert stats_b.status_code == 200
    assert stats_b.json()["total_events"] == 0


@pytest.mark.asyncio
async def test_e2e_multi_format_cascade_processing(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify end-to-end processing and searchability for multiple log formats (Syslog, JSON, CEF)."""
    signup = await async_client.post(
        "/auth/signup",
        json={"email": "format_tester@corp.com", "password": "Password#123", "full_name": "Format Tester"},
    )
    user_id = signup.json()["id"]
    token = signup.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    engine = LogMorphEngine()
    storage = get_storage_adapter()

    test_logs = [
        # Syslog
        ("<13>1 2026-10-30T10:00:00Z web01 nginx 501 - - GET /api/v1/users 200", LogFormatEnum.SYSLOG),
        # JSON
        ('{"timestamp": "2026-10-30T10:05:00Z", "level": "ERROR", "message": "Database pool timed out"}', LogFormatEnum.JSON),
        # CEF
        ("CEF:0|Security|Firewall|1.0|100|Port Scan Detected|8|src=10.0.0.1 dst=10.0.0.2", LogFormatEnum.CEF),
    ]

    for raw, expected_format in test_logs:
        res = engine.process(raw_log=raw, tenant_id=user_id)
        assert res.success is True
        assert res.event is not None
        assert res.event.detected_format == expected_format
        await storage.store_event(async_db, res.event)

    # Search for all events
    search_resp = await async_client.get(
        "/api/v1/events",
        headers=headers,
    )
    assert search_resp.status_code == 200
    items = search_resp.json()["events"]
    assert len(items) == 3

    formats_found = {item["detected_format"].upper() for item in items}
    assert formats_found == {"SYSLOG", "JSON", "CEF"}
