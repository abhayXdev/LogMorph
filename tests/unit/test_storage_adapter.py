"""Comprehensive unit test suite for PostgreSQL Hot Storage Adapter.

Tests single-event persistence, bulk batch transactions, multi-tenant isolation,
multi-vector query filtering, pagination controls, and tenant analytics aggregations.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.db.models import User
from logmorph.domain.uls import (
    DestinationInfo,
    EnrichmentContext,
    GeoIPContext,
    LogFormatEnum,
    ParsingTierEnum,
    SecurityContext,
    SeverityEnum,
    SourceInfo,
    UniversalLogEvent,
)
from logmorph.schemas.storage import LogQueryFilter
from logmorph.storage.adapter import (
    PostgresStorageAdapter,
    get_storage_adapter,
)


@pytest.fixture
def storage_adapter() -> PostgresStorageAdapter:
    """Return storage adapter instance."""
    return PostgresStorageAdapter()


@pytest.fixture
async def tenant_user(async_db: AsyncSession) -> User:
    """Create a primary tenant user for database foreign key satisfaction."""
    user = User(
        email="tenant_a@example.com",
        full_name="Tenant Alpha",
        hashed_password="bcrypt_hashed_password",
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)
    return user


@pytest.fixture
async def tenant_user_b(async_db: AsyncSession) -> User:
    """Create a secondary tenant user for multi-tenant isolation verification."""
    user = User(
        email="tenant_b@example.com",
        full_name="Tenant Bravo",
        hashed_password="bcrypt_hashed_password",
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)
    return user


# ==============================================================================
# 1. Single Event Persistence Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_store_single_event(
    async_db: AsyncSession,
    storage_adapter: PostgresStorageAdapter,
    tenant_user: User,
) -> None:
    """Single UniversalLogEvent is persisted with full relational and JSON telemetry."""
    event = UniversalLogEvent(
        tenant_id=tenant_user.id,
        raw_log="Oct 30 10:00:00 web sshd[10]: Failed password for root from 8.8.8.8 port 22",
        detected_format=LogFormatEnum.SYSLOG,
        severity=SeverityEnum.ERROR,
        action="LOGIN_FAILED",
        source=SourceInfo(ip="8.8.8.8", port=22),
        destination=DestinationInfo(ip="10.0.0.1", port=22),
        security=SecurityContext(user="root", threat_id="Brute Force Attacker"),
        parsed_by=ParsingTierEnum.RULE,
        attributes={"protocol": "ssh2", "attempt": 3},
        enrichment=EnrichmentContext(
            geoip=GeoIPContext(country="United States", country_code="US"),
            threat_match=True,
            mitre_technique="T1110.001",
            mitre_tactic="TA0006",
        ),
    )

    record = await storage_adapter.store_event(async_db, event)
    assert record.id is not None
    assert record.tenant_id == tenant_user.id
    assert record.event_id == event.event_id
    assert record.source_ip == "8.8.8.8"
    assert record.threat_matched is True
    assert record.mitre_technique == "T1110.001"
    assert record.geoip_country == "United States"
    assert "protocol" in record.attributes_json


# ==============================================================================
# 2. Bulk Batch Transaction Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_store_batch_events(
    async_db: AsyncSession,
    storage_adapter: PostgresStorageAdapter,
    tenant_user: User,
) -> None:
    """Batch of UniversalLogEvents is persisted atomically within a single transaction."""
    events = [
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log=f"Batch log entry sequence #{i}",
            detected_format=LogFormatEnum.JSON,
            action="LOG_WRITE",
            attributes={"index": i},
        )
        for i in range(15)
    ]

    count = await storage_adapter.store_batch(async_db, events)
    assert count == 15

    # Verify query returns all 15 records
    records, total = await storage_adapter.query_logs(async_db, tenant_id=tenant_user.id)
    assert total == 15
    assert len(records) == 15


# ==============================================================================
# 3. Multi-Tenant Isolation Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_strict_multi_tenant_isolation(
    async_db: AsyncSession,
    storage_adapter: PostgresStorageAdapter,
    tenant_user: User,
    tenant_user_b: User,
) -> None:
    """Logs belonging to Tenant A must never leak into Tenant B queries."""
    # Store 5 events for Tenant A
    events_a = [
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log=f"Tenant A Confidential Log {i}",
            detected_format=LogFormatEnum.JSON,
        )
        for i in range(5)
    ]
    await storage_adapter.store_batch(async_db, events_a)

    # Store 3 events for Tenant B
    events_b = [
        UniversalLogEvent(
            tenant_id=tenant_user_b.id,
            raw_log=f"Tenant B Private Event {i}",
            detected_format=LogFormatEnum.CEF,
        )
        for i in range(3)
    ]
    await storage_adapter.store_batch(async_db, events_b)

    # Tenant A Query
    records_a, total_a = await storage_adapter.query_logs(async_db, tenant_id=tenant_user.id)
    assert total_a == 5
    assert all(r.tenant_id == tenant_user.id for r in records_a)
    assert all("Tenant A" in r.raw_log for r in records_a)

    # Tenant B Query
    records_b, total_b = await storage_adapter.query_logs(async_db, tenant_id=tenant_user_b.id)
    assert total_b == 3
    assert all(r.tenant_id == tenant_user_b.id for r in records_b)
    assert all("Tenant B" in r.raw_log for r in records_b)

    # Tenant B attempts to fetch Tenant A's event by ID
    target_event_id = events_a[0].event_id
    leak_attempt = await storage_adapter.get_log_by_id(
        async_db, tenant_id=tenant_user_b.id, event_id=target_event_id
    )
    assert leak_attempt is None


# ==============================================================================
# 4. Multi-Vector Analytical Query Filtering Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_query_filter_by_severity_and_format(
    async_db: AsyncSession,
    storage_adapter: PostgresStorageAdapter,
    tenant_user: User,
) -> None:
    """Filter logs by severity enum and source format."""
    events = [
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Critical database crash",
            detected_format=LogFormatEnum.JSON,
            severity=SeverityEnum.CRITICAL,
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Informational heartbeat",
            detected_format=LogFormatEnum.JSON,
            severity=SeverityEnum.INFORMATIONAL,
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Warning disk space",
            detected_format=LogFormatEnum.SYSLOG,
            severity=SeverityEnum.WARNING,
        ),
    ]
    await storage_adapter.store_batch(async_db, events)

    # Filter by Severity = CRITICAL
    crit_filter = LogQueryFilter(severity=SeverityEnum.CRITICAL)
    crit_res, crit_total = await storage_adapter.query_logs(
        async_db, tenant_id=tenant_user.id, filter_params=crit_filter
    )
    assert crit_total == 1
    assert crit_res[0].severity == "CRITICAL"

    # Filter by Format = SYSLOG
    syslog_filter = LogQueryFilter(detected_format=LogFormatEnum.SYSLOG)
    sys_res, sys_total = await storage_adapter.query_logs(
        async_db, tenant_id=tenant_user.id, filter_params=syslog_filter
    )
    assert sys_total == 1
    assert sys_res[0].detected_format == "SYSLOG"


@pytest.mark.asyncio
async def test_query_filter_by_threat_and_mitre(
    async_db: AsyncSession,
    storage_adapter: PostgresStorageAdapter,
    tenant_user: User,
) -> None:
    """Filter logs by threat_matched boolean and MITRE ATT&CK technique."""
    events = [
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="C2 Beacon detected",
            detected_format=LogFormatEnum.JSON,
            enrichment=EnrichmentContext(
                threat_match=True,
                mitre_technique="T1071.001",
            ),
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Port scan detected",
            detected_format=LogFormatEnum.JSON,
            enrichment=EnrichmentContext(
                threat_match=False,
                mitre_technique="T1046",
            ),
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Clean traffic",
            detected_format=LogFormatEnum.JSON,
        ),
    ]
    await storage_adapter.store_batch(async_db, events)

    # Filter Threat Matched = True
    threat_filter = LogQueryFilter(threat_matched=True)
    t_res, t_total = await storage_adapter.query_logs(
        async_db, tenant_id=tenant_user.id, filter_params=threat_filter
    )
    assert t_total == 1
    assert t_res[0].threat_matched is True

    # Filter MITRE Technique = T1046
    mitre_filter = LogQueryFilter(mitre_technique="T1046")
    m_res, m_total = await storage_adapter.query_logs(
        async_db, tenant_id=tenant_user.id, filter_params=mitre_filter
    )
    assert m_total == 1
    assert m_res[0].mitre_technique == "T1046"


@pytest.mark.asyncio
async def test_query_filter_by_time_range(
    async_db: AsyncSession,
    storage_adapter: PostgresStorageAdapter,
    tenant_user: User,
) -> None:
    """Filter logs within a specific temporal window."""
    base_time = datetime(2026, 10, 30, 12, 0, 0, tzinfo=UTC)

    events = [
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Event T-2h",
            timestamp=base_time - timedelta(hours=2),
            detected_format=LogFormatEnum.JSON,
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Event T-1h",
            timestamp=base_time - timedelta(hours=1),
            detected_format=LogFormatEnum.JSON,
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Event T0",
            timestamp=base_time,
            detected_format=LogFormatEnum.JSON,
        ),
    ]
    await storage_adapter.store_batch(async_db, events)

    time_filter = LogQueryFilter(
        start_time=base_time - timedelta(minutes=90),
        end_time=base_time - timedelta(minutes=30),
    )
    res, total = await storage_adapter.query_logs(
        async_db, tenant_id=tenant_user.id, filter_params=time_filter
    )
    assert total == 1
    assert res[0].raw_log == "Event T-1h"


@pytest.mark.asyncio
async def test_query_substring_search(
    async_db: AsyncSession,
    storage_adapter: PostgresStorageAdapter,
    tenant_user: User,
) -> None:
    """Substring search across raw log, action, or user fields."""
    events = [
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Inbound attack detected from APT29 campaign",
            detected_format=LogFormatEnum.JSON,
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Normal user browsing",
            detected_format=LogFormatEnum.JSON,
            security=SecurityContext(user="apt_researcher"),
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="System routine update",
            detected_format=LogFormatEnum.JSON,
        ),
    ]
    await storage_adapter.store_batch(async_db, events)

    search_filter = LogQueryFilter(search_term="apt")
    res, total = await storage_adapter.query_logs(
        async_db, tenant_id=tenant_user.id, filter_params=search_filter
    )
    assert total == 2


# ==============================================================================
# 5. Pagination Controls Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_query_pagination(
    async_db: AsyncSession,
    storage_adapter: PostgresStorageAdapter,
    tenant_user: User,
) -> None:
    """Deterministic limit and offset pagination across stored records."""
    events = [
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log=f"Paginated log #{i:02d}",
            timestamp=datetime(2026, 10, 30, 10, 0, i, tzinfo=UTC),
            detected_format=LogFormatEnum.JSON,
        )
        for i in range(12)
    ]
    await storage_adapter.store_batch(async_db, events)

    # Page 1 (offset=0, limit=5)
    page1, total1 = await storage_adapter.query_logs(
        async_db, tenant_id=tenant_user.id, filter_params=LogQueryFilter(limit=5, offset=0)
    )
    assert total1 == 12
    assert len(page1) == 5

    # Page 2 (offset=5, limit=5)
    page2, total2 = await storage_adapter.query_logs(
        async_db, tenant_id=tenant_user.id, filter_params=LogQueryFilter(limit=5, offset=5)
    )
    assert total2 == 12
    assert len(page2) == 5
    # Distinct records
    assert {r.id for r in page1}.isdisjoint({r.id for r in page2})

    # Page 3 (offset=10, limit=5) -> Only 2 remaining
    page3, total3 = await storage_adapter.query_logs(
        async_db, tenant_id=tenant_user.id, filter_params=LogQueryFilter(limit=5, offset=10)
    )
    assert len(page3) == 2


# ==============================================================================
# 6. Tenant Analytics & Security Telemetry Aggregation
# ==============================================================================


@pytest.mark.asyncio
async def test_tenant_statistics_aggregation(
    async_db: AsyncSession,
    storage_adapter: PostgresStorageAdapter,
    tenant_user: User,
) -> None:
    """get_tenant_stats aggregates breakdown by severity, format, MITRE, and GeoIP."""
    events = [
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Critical C2 beacon",
            detected_format=LogFormatEnum.JSON,
            severity=SeverityEnum.CRITICAL,
            enrichment=EnrichmentContext(
                geoip=GeoIPContext(country="United States"),
                threat_match=True,
                mitre_technique="T1071.001",
            ),
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Error failed password",
            detected_format=LogFormatEnum.SYSLOG,
            severity=SeverityEnum.ERROR,
            enrichment=EnrichmentContext(
                geoip=GeoIPContext(country="Germany"),
                threat_match=False,
                mitre_technique="T1110.001",
            ),
            attributes={"is_duplicate": True},
        ),
        UniversalLogEvent(
            tenant_id=tenant_user.id,
            raw_log="Info heartbeat",
            detected_format=LogFormatEnum.JSON,
            severity=SeverityEnum.INFORMATIONAL,
        ),
    ]
    await storage_adapter.store_batch(async_db, events)

    stats = await storage_adapter.get_tenant_stats(async_db, tenant_id=tenant_user.id)
    assert stats.tenant_id == tenant_user.id
    assert stats.total_logs == 3
    assert stats.threat_count == 1
    assert stats.duplicate_count == 1
    assert stats.severity_breakdown.get("CRITICAL") == 1
    assert stats.severity_breakdown.get("ERROR") == 1
    assert stats.format_breakdown.get("JSON") == 2
    assert stats.format_breakdown.get("SYSLOG") == 1
    assert stats.top_mitre_techniques.get("T1071.001") == 1
    assert stats.top_countries.get("United States") == 1


def test_default_singleton_accessor() -> None:
    """get_storage_adapter returns a configured PostgresStorageAdapter instance."""
    adapter = get_storage_adapter()
    assert isinstance(adapter, PostgresStorageAdapter)
