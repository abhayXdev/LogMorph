"""Integration tests for API Keys, Sandbox parser, Log Sources, and Tenant Stats endpoints."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.security import create_access_token, hash_password
from logmorph.db.models import LogSource, User
from logmorph.domain.uls import (
    EnrichmentContext,
    LogFormatEnum,
    ParsingTierEnum,
    SeverityEnum,
    UniversalLogEvent,
)
from logmorph.storage.adapter import get_storage_adapter


async def _create_test_tenant_user(
    session: AsyncSession,
    email: str = "tenant_stats@logmorph.io",
) -> tuple[User, str]:
    """Create test tenant and return user entity and JWT access token."""
    user = User(
        email=email,
        full_name="Stats Tenant",
        hashed_password=hash_password("Pass#1234"),
        is_verified=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    token = create_access_token(subject=user.id, email=user.email)
    return user, token


# ==============================================================================
# 1. API Keys Management Lifecycle Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_api_keys_crud_lifecycle(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify provisioning, listing, using, and revoking API keys."""
    _, token = await _create_test_tenant_user(async_db, email="keymaster@logmorph.io")
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create API key
    create_resp = await async_client.post(
        "/api/v1/keys",
        json={"name": "Edge Firewall Key"},
        headers=headers,
    )
    assert create_resp.status_code == 201
    created_data = create_resp.json()
    assert created_data["name"] == "Edge Firewall Key"
    assert "key" in created_data
    assert created_data["key"].startswith("lm_live_")
    key_id = created_data["id"]
    raw_key = created_data["key"]

    # 2. List API keys (shows masked prefix)
    list_resp = await async_client.get("/api/v1/keys", headers=headers)
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert list_data["total"] == 1
    assert list_data["keys"][0]["id"] == key_id
    assert "****" in list_data["keys"][0]["key_prefix"]

    # 3. Use provisioned key to ingest log
    ingest_resp = await async_client.post(
        "/api/v1/ingest",
        json={"raw_log": "Test syslog from newly created key", "source": "firewall"},
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert ingest_resp.status_code == 202

    # 4. Revoke API key
    del_resp = await async_client.delete(f"/api/v1/keys/{key_id}", headers=headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["key_id"] == key_id

    # 5. Using revoked key must fail with 401
    revoked_resp = await async_client.post(
        "/api/v1/ingest",
        json={"raw_log": "Log after revocation", "source": "firewall"},
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert revoked_resp.status_code == 401


# ==============================================================================
# 2. Sandbox Parser Playground Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_sandbox_parse_syslog_log(
    async_client: AsyncClient,
):
    """Verify live parsing of arbitrary syslog string in sandbox without storage."""
    raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
    response = await async_client.post(
        "/api/v1/sandbox/parse",
        json={"raw_log": raw},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["detected_format"] == "SYSLOG"
    assert data["parsed_by"] in ("RULE", "TEMPLATE", "LLM", "FALLBACK")
    assert "event" in data
    assert data["event"]["severity"] in ("CRITICAL", "INFORMATIONAL", "NOTICE")
    assert data["event"]["raw_log"] == raw


@pytest.mark.asyncio
async def test_sandbox_parse_json_log(
    async_client: AsyncClient,
):
    """Verify live parsing of JSON log format in sandbox."""
    raw = '{"timestamp": "2026-11-10T12:00:00Z", "level": "error", "message": "database connection failed"}'
    response = await async_client.post(
        "/api/v1/sandbox/parse",
        json={"raw_log": raw},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["detected_format"] == "JSON"
    assert data["event"]["detected_format"] == "JSON"


# ==============================================================================
# 3. Log Sources Management Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_log_sources_crud_and_isolation(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify source registration, listing, deletion, and cross-tenant isolation."""
    tenant_a, token_a = await _create_test_tenant_user(async_db, email="source_a@logmorph.io")
    _, token_b = await _create_test_tenant_user(async_db, email="source_b@logmorph.io")

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # 1. Tenant A registers a source
    create_resp = await async_client.post(
        "/api/v1/sources",
        json={
            "name": "Production Firewall",
            "type": "SYSLOG",
            "description": "Edge firewall collector",
        },
        headers=headers_a,
    )
    assert create_resp.status_code == 201
    source_data = create_resp.json()
    assert source_data["name"] == "Production Firewall"
    assert source_data["type"] == "SYSLOG"
    source_id = source_data["id"]

    # 2. Tenant A lists sources -> finds 1
    list_a = (await async_client.get("/api/v1/sources", headers=headers_a)).json()
    assert list_a["total"] == 1
    assert list_a["sources"][0]["id"] == source_id

    # 3. Tenant B lists sources -> finds 0 (Isolation)
    list_b = (await async_client.get("/api/v1/sources", headers=headers_b)).json()
    assert list_b["total"] == 0

    # 4. Tenant B cannot delete Tenant A's source -> returns 404
    del_fail = await async_client.delete(f"/api/v1/sources/{source_id}", headers=headers_b)
    assert del_fail.status_code == 404

    # 5. Tenant A deletes their source -> returns 200
    del_ok = await async_client.delete(f"/api/v1/sources/{source_id}", headers=headers_a)
    assert del_ok.status_code == 200
    assert del_ok.json()["source_id"] == source_id


# ==============================================================================
# 4. Tenant Security Analytics & Stats Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_stats_endpoints(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify all /api/v1/stats endpoints return matching contracts."""
    tenant, token = await _create_test_tenant_user(async_db, email="stats_all@logmorph.io")
    adapter = get_storage_adapter()

    # Seed sample records for tenant
    t0 = datetime.now(UTC)
    events = [
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_stat_1",
            raw_log="Syslog critical event",
            detected_format=LogFormatEnum.SYSLOG,
            severity=SeverityEnum.CRITICAL,
            parsed_by=ParsingTierEnum.RULE,
            enrichment=EnrichmentContext(threat_match=True, mitre_technique="T1110"),
            timestamp=t0 - timedelta(hours=2),
        ),
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_stat_2",
            raw_log="JSON info event",
            detected_format=LogFormatEnum.JSON,
            severity=SeverityEnum.INFORMATIONAL,
            parsed_by=ParsingTierEnum.TEMPLATE,
            timestamp=t0 - timedelta(hours=1),
        ),
    ]
    await adapter.store_batch(async_db, events)

    # Seed a log source for active_sources count
    source = LogSource(name="Test Source", source_type="SYSLOG", tenant_id=tenant.id)
    async_db.add(source)
    await async_db.commit()

    headers = {"Authorization": f"Bearer {token}"}

    # 1. Overview
    overview = (await async_client.get("/api/v1/stats/overview", headers=headers)).json()
    assert overview["total_events"] == 2
    assert overview["active_sources"] == 1
    assert "avg_processing_ms" in overview

    # 2. Timeline
    timeline = (await async_client.get("/api/v1/stats/timeline?period=24h", headers=headers)).json()
    assert timeline["period"] == "24h"
    assert len(timeline["data"]) > 0

    # 3. Formats
    formats = (await async_client.get("/api/v1/stats/formats", headers=headers)).json()
    assert len(formats["formats"]) == 2
    format_names = [f["format"] for f in formats["formats"]]
    assert "SYSLOG" in format_names
    assert "JSON" in format_names

    # 4. Severity
    severity = (await async_client.get("/api/v1/stats/severity", headers=headers)).json()
    assert len(severity["severity"]) > 0
    crit_item = next(s for s in severity["severity"] if s["level"] == "CRITICAL")
    assert crit_item["count"] == 1
    assert crit_item["color"] == "#E11D48"

    # 5. Threats
    threats = (await async_client.get("/api/v1/stats/threats", headers=headers)).json()
    assert threats["total_threats_detected"] == 1
    assert len(threats["top_techniques"]) == 1
    assert threats["top_techniques"][0]["technique"] == "T1110"

    # 6. Cascade
    cascade = (await async_client.get("/api/v1/stats/cascade", headers=headers)).json()
    assert len(cascade["tiers"]) == 4
    tier_names = [t["tier"] for t in cascade["tiers"]]
    assert "RULE" in tier_names
    assert "TEMPLATE" in tier_names
