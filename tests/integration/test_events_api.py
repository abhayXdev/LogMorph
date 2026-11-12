"""Integration tests for Tenant-Isolated Search and Event Lifecycle API endpoints."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.keys import generate_api_key
from logmorph.core.security import create_access_token, hash_password
from logmorph.db.models import ApiKey, User
from logmorph.domain.uls import (
    EnrichmentContext,
    GeoIPContext,
    LogFormatEnum,
    ParsingTierEnum,
    SeverityEnum,
    SourceInfo,
    UniversalLogEvent,
)
from logmorph.storage.adapter import get_storage_adapter


async def _create_test_tenant(
    session: AsyncSession,
    email: str = "analyst@tenant.com",
    full_name: str = "Security Analyst",
) -> tuple[User, str, str]:
    """Helper to create a tenant with valid JWT access token and API key."""
    user = User(
        email=email,
        full_name=full_name,
        hashed_password=hash_password("AnalystPass#2026"),
        is_verified=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    jwt_token = create_access_token(subject=user.id, email=user.email)

    key_data = generate_api_key()
    api_key = ApiKey(
        name="Analyst Automation Key",
        key_hash=key_data.key_hash,
        key_prefix=key_data.key_prefix,
        is_active=True,
        user_id=user.id,
    )
    session.add(api_key)
    await session.commit()
    await session.refresh(api_key)

    return user, jwt_token, key_data.raw_key


# ==============================================================================
# 1. Authentication Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_events_list_missing_auth_header_fails_401(async_client: AsyncClient):
    """Verify that accessing /api/v1/events without auth returns 401."""
    response = await async_client.get("/api/v1/events")
    assert response.status_code == 401
    assert "detail" in response.json()


@pytest.mark.asyncio
async def test_events_list_invalid_jwt_fails_401(async_client: AsyncClient):
    """Verify that an invalid or bogus JWT token returns 401."""
    headers = {"Authorization": "Bearer bogus.invalid.jwttoken"}
    response = await async_client.get("/api/v1/events", headers=headers)
    assert response.status_code == 401
    assert response.json()["error_code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_events_list_with_jwt_bearer_token(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify authenticated request using JWT Bearer token succeeds."""
    _, jwt_token, _ = await _create_test_tenant(async_db)
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = await async_client.get("/api/v1/events", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "events" in data
    assert "pagination" in data
    assert data["pagination"]["total"] == 0


@pytest.mark.asyncio
async def test_events_list_with_api_key_bearer_and_x_api_key(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify authenticated request using API Key via Authorization or X-API-Key."""
    _, _, raw_key = await _create_test_tenant(async_db, email="apikey-user@soc.com")

    # Authorization: Bearer <api_key>
    resp1 = await async_client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {raw_key}"},
    )
    assert resp1.status_code == 200

    # X-API-Key: <api_key>
    resp2 = await async_client.get(
        "/api/v1/events",
        headers={"X-API-Key": raw_key},
    )
    assert resp2.status_code == 200


# ==============================================================================
# 2. Multi-Tenant Isolation Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_strict_multi_tenant_isolation_on_events_list(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify Tenant A cannot view, retrieve, or query Tenant B's events."""
    tenant_a, token_a, _ = await _create_test_tenant(async_db, email="tenant_a@soc.com")
    tenant_b, token_b, _ = await _create_test_tenant(async_db, email="tenant_b@soc.com")

    adapter = get_storage_adapter()

    # Seed events for Tenant A
    event_a = UniversalLogEvent(
        tenant_id=tenant_a.id,
        event_id="evt_tenant_a_1",
        raw_log="Tenant A internal audit log",
        detected_format=LogFormatEnum.SYSLOG,
        severity=SeverityEnum.NOTICE,
    )
    # Seed events for Tenant B
    event_b = UniversalLogEvent(
        tenant_id=tenant_b.id,
        event_id="evt_tenant_b_1",
        raw_log="Tenant B top-secret security incident",
        detected_format=LogFormatEnum.JSON,
        severity=SeverityEnum.CRITICAL,
    )
    await adapter.store_batch(async_db, [event_a, event_b])

    # Query as Tenant A
    resp_a = await async_client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert resp_a.status_code == 200
    events_a = resp_a.json()["events"]
    assert len(events_a) == 1
    assert events_a[0]["event_id"] == "evt_tenant_a_1"

    # Query as Tenant B
    resp_b = await async_client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp_b.status_code == 200
    events_b = resp_b.json()["events"]
    assert len(events_b) == 1
    assert events_b[0]["event_id"] == "evt_tenant_b_1"


# ==============================================================================
# 3. Pagination Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_events_pagination(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify deterministic pagination metadata and slicing across pages."""
    tenant, token, _ = await _create_test_tenant(async_db, email="pager@soc.com")
    adapter = get_storage_adapter()

    base_time = datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC)
    events = [
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id=f"evt_page_{i}",
            raw_log=f"Log event #{i}",
            timestamp=base_time + timedelta(minutes=i),
            detected_format=LogFormatEnum.JSON,
        )
        for i in range(7)
    ]
    await adapter.store_batch(async_db, events)

    headers = {"Authorization": f"Bearer {token}"}

    # Page 1 (limit 3): items 0, 1, 2
    p1 = (await async_client.get("/api/v1/events?page=1&limit=3", headers=headers)).json()
    assert len(p1["events"]) == 3
    assert p1["pagination"] == {"page": 1, "limit": 3, "total": 7, "total_pages": 3}

    # Page 2 (limit 3): items 3, 4, 5
    p2 = (await async_client.get("/api/v1/events?page=2&limit=3", headers=headers)).json()
    assert len(p2["events"]) == 3
    assert p2["pagination"]["page"] == 2

    # Page 3 (limit 3): item 6
    p3 = (await async_client.get("/api/v1/events?page=3&limit=3", headers=headers)).json()
    assert len(p3["events"]) == 1
    assert p3["pagination"]["page"] == 3

    # Page 4 (limit 3): empty
    p4 = (await async_client.get("/api/v1/events?page=4&limit=3", headers=headers)).json()
    assert len(p4["events"]) == 0


# ==============================================================================
# 4. Multi-Vector Filtering Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_events_filter_by_severity_and_format(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify filtering by severity level and detected format."""
    tenant, token, _ = await _create_test_tenant(async_db, email="filter@soc.com")
    adapter = get_storage_adapter()

    events = [
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_crit_syslog",
            raw_log="Critical syslog",
            detected_format=LogFormatEnum.SYSLOG,
            severity=SeverityEnum.CRITICAL,
        ),
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_info_json",
            raw_log="Info json",
            detected_format=LogFormatEnum.JSON,
            severity=SeverityEnum.INFORMATIONAL,
        ),
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_warn_cef",
            raw_log="Warn cef",
            detected_format=LogFormatEnum.CEF,
            severity=SeverityEnum.WARNING,
        ),
    ]
    await adapter.store_batch(async_db, events)

    headers = {"Authorization": f"Bearer {token}"}

    # Filter by severity=CRITICAL
    res1 = (await async_client.get("/api/v1/events?severity=CRITICAL", headers=headers)).json()
    assert res1["pagination"]["total"] == 1
    assert res1["events"][0]["event_id"] == "evt_crit_syslog"

    # Filter by format=JSON
    res2 = (await async_client.get("/api/v1/events?format=JSON", headers=headers)).json()
    assert res2["pagination"]["total"] == 1
    assert res2["events"][0]["event_id"] == "evt_info_json"


@pytest.mark.asyncio
async def test_events_filter_by_time_range(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify filtering by temporal range (from / to ISO timestamps)."""
    tenant, token, _ = await _create_test_tenant(async_db, email="time@soc.com")
    adapter = get_storage_adapter()

    t0 = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)
    events = [
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_t1",
            raw_log="Log 1",
            timestamp=t0 - timedelta(hours=3),
            detected_format=LogFormatEnum.JSON,
        ),
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_t2",
            raw_log="Log 2",
            timestamp=t0 - timedelta(hours=1),
            detected_format=LogFormatEnum.JSON,
        ),
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_t3",
            raw_log="Log 3",
            timestamp=t0 + timedelta(hours=1),
            detected_format=LogFormatEnum.JSON,
        ),
    ]
    await adapter.store_batch(async_db, events)

    headers = {"Authorization": f"Bearer {token}"}
    from_str = (t0 - timedelta(hours=2)).isoformat()
    to_str = (t0).isoformat()

    resp = await async_client.get(
        "/api/v1/events",
        params={"from": from_str, "to": to_str},
        headers=headers,
    )
    assert resp.status_code == 200
    res = resp.json()
    assert res["pagination"]["total"] == 1
    assert res["events"][0]["event_id"] == "evt_t2"


@pytest.mark.asyncio
async def test_events_filter_by_threat_matched_and_mitre(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify filtering by threat intelligence match and MITRE ATT&CK technique."""
    tenant, token, _ = await _create_test_tenant(async_db, email="threat-filter@soc.com")
    adapter = get_storage_adapter()

    events = [
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_threat_true",
            raw_log="Threat true log",
            detected_format=LogFormatEnum.JSON,
            enrichment=EnrichmentContext(threat_match=True, mitre_technique="T1110"),
        ),
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_threat_false",
            raw_log="Threat false log",
            detected_format=LogFormatEnum.JSON,
            enrichment=EnrichmentContext(threat_match=False, mitre_technique="T1046"),
        ),
    ]
    await adapter.store_batch(async_db, events)

    headers = {"Authorization": f"Bearer {token}"}

    # Threat matched = true
    res1 = (await async_client.get("/api/v1/events?threat_matched=true", headers=headers)).json()
    assert res1["pagination"]["total"] == 1
    assert res1["events"][0]["event_id"] == "evt_threat_true"

    # MITRE technique = T1046
    res2 = (await async_client.get("/api/v1/events?mitre_technique=T1046", headers=headers)).json()
    assert res2["pagination"]["total"] == 1
    assert res2["events"][0]["event_id"] == "evt_threat_false"


# ==============================================================================
# 5. Single Event Detail Retrieval Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_get_single_event_detail_success(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify retrieving detailed representation of an event with all context."""
    tenant, token, _ = await _create_test_tenant(async_db, email="detail@soc.com")
    adapter = get_storage_adapter()

    event = UniversalLogEvent(
        tenant_id=tenant.id,
        event_id="evt_detail_001",
        raw_log="<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
        detected_format=LogFormatEnum.SYSLOG,
        severity=SeverityEnum.CRITICAL,
        action="LOGIN_FAILED",
        parsed_by=ParsingTierEnum.RULE,
        source=SourceInfo(ip="192.168.1.50", port=22),
        enrichment=EnrichmentContext(
            threat_match=False,
            mitre_technique="T1110 - Brute Force",
            mitre_tactic="Credential Access",
            geoip=GeoIPContext(country="India", country_code="IN", city="Mumbai"),
        ),
        attributes={"facility": "auth", "priority": 34, "hostname": "mymachine"},
    )
    await adapter.store_event(async_db, event)

    headers = {"Authorization": f"Bearer {token}"}
    response = await async_client.get("/api/v1/events/evt_detail_001", headers=headers)
    assert response.status_code == 200

    data = response.json()
    assert data["event_id"] == "evt_detail_001"
    assert data["detected_format"] == "SYSLOG"
    assert data["severity"] == "CRITICAL"
    assert data["action"] == "LOGIN_FAILED"
    assert data["parsed_by"] == "RULE"
    assert data["source"]["ip"] == "192.168.1.50"
    assert data["source"]["hostname"] == "mymachine"
    assert data["enrichment"]["threat_match"] is False
    assert data["enrichment"]["mitre_technique"] == "T1110 - Brute Force"
    assert data["enrichment"]["geoip"]["country"] == "India"
    assert data["attributes"]["facility"] == "auth"


@pytest.mark.asyncio
async def test_get_single_event_detail_cross_tenant_isolation_returns_404(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify requesting another tenant's event returns 404 Not Found."""
    tenant_a, token_a, _ = await _create_test_tenant(async_db, email="tenant_a_detail@soc.com")
    tenant_b, _, _ = await _create_test_tenant(async_db, email="tenant_b_detail@soc.com")

    adapter = get_storage_adapter()
    event_b = UniversalLogEvent(
        tenant_id=tenant_b.id,
        event_id="evt_owned_by_b",
        raw_log="Tenant B secret log",
        detected_format=LogFormatEnum.JSON,
    )
    await adapter.store_event(async_db, event_b)

    # Tenant A attempts to fetch Tenant B's event
    headers = {"Authorization": f"Bearer {token_a}"}
    response = await async_client.get("/api/v1/events/evt_owned_by_b", headers=headers)
    assert response.status_code == 404
    assert response.json()["error_code"] == "NOT_FOUND"


@pytest.mark.asyncio
async def test_get_single_event_detail_nonexistent_returns_404(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify requesting a nonexistent event ID returns 404 Not Found."""
    _, token, _ = await _create_test_tenant(async_db, email="notfound@soc.com")
    headers = {"Authorization": f"Bearer {token}"}
    response = await async_client.get("/api/v1/events/evt_does_not_exist", headers=headers)
    assert response.status_code == 404


# ==============================================================================
# 6. Full-Text Search & Relevance Scoring Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_search_events_full_text_and_relevance_scores(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify full-text search computes scores and matches raw log patterns."""
    tenant, token, _ = await _create_test_tenant(async_db, email="searcher@soc.com")
    adapter = get_storage_adapter()

    events = [
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_search_1",
            raw_log="Failed password for invalid user admin from 192.168.1.10",
            detected_format=LogFormatEnum.SYSLOG,
            severity=SeverityEnum.CRITICAL,
        ),
        UniversalLogEvent(
            tenant_id=tenant.id,
            event_id="evt_search_2",
            raw_log="Accepted publickey for ubuntu from 10.0.0.5",
            detected_format=LogFormatEnum.SYSLOG,
            severity=SeverityEnum.INFORMATIONAL,
        ),
    ]
    await adapter.store_batch(async_db, events)

    headers = {"Authorization": f"Bearer {token}"}

    # Search for "Failed password"
    response = await async_client.get("/api/v1/events/search?q=Failed+password", headers=headers)
    assert response.status_code == 200

    data = response.json()
    assert data["query"] == "Failed password"
    assert data["total"] == 1
    assert len(data["results"]) == 1

    result = data["results"][0]
    assert result["event_id"] == "evt_search_1"
    assert result["score"] >= 0.70
    assert result["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_search_events_empty_results(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify search returns empty list when no matches are found."""
    _, token, _ = await _create_test_tenant(async_db, email="empty-search@soc.com")
    headers = {"Authorization": f"Bearer {token}"}

    response = await async_client.get("/api/v1/events/search?q=nonexistentpatternxyz", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["results"] == []


@pytest.mark.asyncio
async def test_search_events_route_ordering_not_intercepted_by_event_id(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify /events/search is not captured as /events/{event_id} with event_id='search'."""
    _, token, _ = await _create_test_tenant(async_db, email="route-order@soc.com")
    headers = {"Authorization": f"Bearer {token}"}

    # Calling search with required param 'q' must hit search_events, NOT get_event_by_id
    response = await async_client.get("/api/v1/events/search?q=test", headers=headers)
    assert response.status_code == 200
    assert "query" in response.json()


# ==============================================================================
# 7. Lifecycle Deletion Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_delete_event_success(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify an event owned by the calling tenant can be safely deleted."""
    tenant, token, _ = await _create_test_tenant(async_db, email="deleter@soc.com")
    adapter = get_storage_adapter()

    event = UniversalLogEvent(
        tenant_id=tenant.id,
        event_id="evt_to_delete",
        raw_log="Log to be deleted",
        detected_format=LogFormatEnum.JSON,
    )
    await adapter.store_event(async_db, event)

    headers = {"Authorization": f"Bearer {token}"}

    # 1. Delete event
    del_resp = await async_client.delete("/api/v1/events/evt_to_delete", headers=headers)
    assert del_resp.status_code == 200
    assert del_resp.json()["event_id"] == "evt_to_delete"

    # 2. Subsequent GET returns 404
    get_resp = await async_client.get("/api/v1/events/evt_to_delete", headers=headers)
    assert get_resp.status_code == 404

    # 3. Subsequent DELETE returns 404
    del_resp2 = await async_client.delete("/api/v1/events/evt_to_delete", headers=headers)
    assert del_resp2.status_code == 404


@pytest.mark.asyncio
async def test_delete_event_cross_tenant_forbidden_returns_404(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify a tenant cannot delete an event belonging to another tenant."""
    tenant_a, token_a, _ = await _create_test_tenant(async_db, email="tenant_a_del@soc.com")
    tenant_b, _, _ = await _create_test_tenant(async_db, email="tenant_b_del@soc.com")

    adapter = get_storage_adapter()
    event_b = UniversalLogEvent(
        tenant_id=tenant_b.id,
        event_id="evt_protected_b",
        raw_log="Tenant B protected log",
        detected_format=LogFormatEnum.JSON,
    )
    await adapter.store_event(async_db, event_b)

    # Tenant A attempts to delete Tenant B's event
    headers = {"Authorization": f"Bearer {token_a}"}
    del_resp = await async_client.delete("/api/v1/events/evt_protected_b", headers=headers)
    assert del_resp.status_code == 404

    # Verify event still exists in DB
    existing = await adapter.get_event_detail(async_db, tenant_id=tenant_b.id, event_id="evt_protected_b")
    assert existing is not None
    assert existing.event_id == "evt_protected_b"
