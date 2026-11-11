"""PostgreSQL Hot Storage Adapter for LogMorph.

Provides high-throughput event persistence, bulk batch transactions, multi-vector
log querying with strict tenant isolation, and tenant analytical security aggregations.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import func
from sqlmodel import col, or_, select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.db.models import LogRecord
from logmorph.domain.uls import UniversalLogEvent
from logmorph.schemas.storage import (
    LogQueryFilter,
    LogRecordRead,
    TenantLogStats,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# 1. Domain / Storage Model Converters
# ==============================================================================


def log_event_to_record(event: UniversalLogEvent) -> LogRecord:
    """Transform canonical UniversalLogEvent into relational LogRecord entity."""
    src_ip = event.source.ip if event.source else None
    src_port = event.source.port if event.source else None
    dst_ip = event.destination.ip if event.destination else None
    dst_port = event.destination.port if event.destination else None
    user_val = event.security.user if event.security else None
    proc_val = event.security.process_name if event.security else None
    threat_id_val = event.security.threat_id if event.security else None

    threat_matched = bool(event.enrichment and event.enrichment.threat_match)
    mitre_tech = event.enrichment.mitre_technique if event.enrichment else None
    mitre_tac = event.enrichment.mitre_tactic if event.enrichment else None
    geoip_ctry = (
        event.enrichment.geoip.country
        if (event.enrichment and event.enrichment.geoip)
        else None
    )

    fmt_str = (
        event.detected_format.value
        if hasattr(event.detected_format, "value")
        else str(event.detected_format)
    )
    sev_str = (
        event.severity.value
        if hasattr(event.severity, "value")
        else str(event.severity)
    )
    tier_str = (
        event.parsed_by.value
        if hasattr(event.parsed_by, "value")
        else str(event.parsed_by)
    )

    return LogRecord(
        tenant_id=event.tenant_id,
        event_id=event.event_id,
        timestamp=event.timestamp,
        ingested_at=event.ingested_at,
        raw_log=event.raw_log,
        detected_format=fmt_str,
        severity=sev_str,
        action=event.action,
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        user=user_val,
        process_name=proc_val,
        parsed_by=tier_str,
        is_duplicate=bool(event.attributes.get("is_duplicate", False)),
        threat_matched=threat_matched,
        threat_id=threat_id_val,
        mitre_technique=mitre_tech,
        mitre_tactic=mitre_tac,
        geoip_country=geoip_ctry,
        attributes_json=json.dumps(event.attributes, default=str),
        enrichment_json=(
            event.enrichment.model_dump_json() if event.enrichment else None
        ),
    )


def record_to_read(record: LogRecord) -> LogRecordRead:
    """Project relational LogRecord into API response model LogRecordRead."""
    attrs: dict[str, Any] = {}
    if record.attributes_json:
        try:
            attrs = json.loads(record.attributes_json)
        except Exception:
            attrs = {}

    return LogRecordRead(
        id=record.id,
        tenant_id=record.tenant_id,
        event_id=record.event_id,
        timestamp=record.timestamp,
        ingested_at=record.ingested_at,
        raw_log=record.raw_log,
        detected_format=record.detected_format,
        severity=record.severity,
        action=record.action,
        source_ip=record.source_ip,
        source_port=record.source_port,
        destination_ip=record.destination_ip,
        destination_port=record.destination_port,
        user=record.user,
        process_name=record.process_name,
        parsed_by=record.parsed_by,
        is_duplicate=record.is_duplicate,
        threat_matched=record.threat_matched,
        threat_id=record.threat_id,
        mitre_technique=record.mitre_technique,
        mitre_tactic=record.mitre_tactic,
        geoip_country=record.geoip_country,
        attributes=attrs,
    )


# ==============================================================================
# 2. PostgreSQL Storage Adapter
# ==============================================================================


class PostgresStorageAdapter:
    """High-performance storage adapter managing LogRecord persistence and search."""

    async def store_event(
        self,
        session: AsyncSession,
        event: UniversalLogEvent,
    ) -> LogRecord:
        """Persist an individual UniversalLogEvent into hot storage."""
        record = log_event_to_record(event)
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return record

    async def store_batch(
        self,
        session: AsyncSession,
        events: list[UniversalLogEvent],
    ) -> int:
        """Persist a batch of UniversalLogEvents within an atomic transaction."""
        if not events:
            return 0

        records = [log_event_to_record(evt) for evt in events]
        session.add_all(records)
        await session.commit()
        return len(records)

    async def query_logs(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        filter_params: LogQueryFilter | None = None,
    ) -> tuple[list[LogRecordRead], int]:
        """Execute multi-vector indexed search strictly bounded by tenant isolation."""
        params = filter_params or LogQueryFilter()
        conditions: list[Any] = [col(LogRecord.tenant_id) == tenant_id]

        if params.start_time:
            conditions.append(col(LogRecord.timestamp) >= params.start_time)
        if params.end_time:
            conditions.append(col(LogRecord.timestamp) <= params.end_time)
        if params.severity:
            conditions.append(col(LogRecord.severity) == params.severity.value)
        if params.detected_format:
            conditions.append(col(LogRecord.detected_format) == params.detected_format.value)
        if params.threat_matched is not None:
            conditions.append(col(LogRecord.threat_matched) == params.threat_matched)
        if params.mitre_technique:
            conditions.append(col(LogRecord.mitre_technique) == params.mitre_technique)
        if params.source_ip:
            conditions.append(col(LogRecord.source_ip) == params.source_ip)
        if params.destination_ip:
            conditions.append(col(LogRecord.destination_ip) == params.destination_ip)
        if params.search_term:
            term = f"%{params.search_term}%"
            conditions.append(
                or_(
                    col(LogRecord.raw_log).ilike(term),
                    col(LogRecord.action).ilike(term),
                    col(LogRecord.user).ilike(term),
                )
            )

        # 1. Total matching count
        count_stmt = select(func.count()).select_from(LogRecord).where(*conditions)
        count_res = await session.exec(count_stmt)
        total_count = int(count_res.one() or 0)

        # 2. Paginated results
        stmt = (
            select(LogRecord)
            .where(*conditions)
            .order_by(col(LogRecord.timestamp).desc())
            .offset(params.offset)
            .limit(params.limit)
        )
        records_res = await session.exec(stmt)
        records = records_res.all()

        items = [record_to_read(r) for r in records]
        return items, total_count

    async def get_log_by_id(
        self,
        session: AsyncSession,
        tenant_id: UUID,
        event_id: str,
    ) -> LogRecordRead | None:
        """Fetch a specific log record ensuring tenant ownership."""
        stmt = select(LogRecord).where(
            col(LogRecord.tenant_id) == tenant_id,
            col(LogRecord.event_id) == event_id,
        )
        res = await session.exec(stmt)
        record = res.first()
        return record_to_read(record) if record else None

    async def get_tenant_stats(
        self,
        session: AsyncSession,
        tenant_id: UUID,
    ) -> TenantLogStats:
        """Compute aggregated security and operational metrics for a tenant."""
        # Total logs count
        total_stmt = select(func.count()).select_from(LogRecord).where(col(LogRecord.tenant_id) == tenant_id)
        total_logs = int((await session.exec(total_stmt)).one() or 0)

        # Threat match count
        threat_stmt = select(func.count()).select_from(LogRecord).where(
            col(LogRecord.tenant_id) == tenant_id,
            col(LogRecord.threat_matched) == True,  # noqa: E712
        )
        threat_count = int((await session.exec(threat_stmt)).one() or 0)

        # Duplicate count
        dup_stmt = select(func.count()).select_from(LogRecord).where(
            col(LogRecord.tenant_id) == tenant_id,
            col(LogRecord.is_duplicate) == True,  # noqa: E712
        )
        duplicate_count = int((await session.exec(dup_stmt)).one() or 0)

        # Severity breakdown
        sev_stmt = (
            select(LogRecord.severity, func.count())
            .where(col(LogRecord.tenant_id) == tenant_id)
            .group_by(col(LogRecord.severity))
        )
        sev_res = (await session.exec(sev_stmt)).all()
        severity_breakdown = {str(k): int(v) for k, v in sev_res if k is not None}

        # Format breakdown
        fmt_stmt = (
            select(LogRecord.detected_format, func.count())
            .where(col(LogRecord.tenant_id) == tenant_id)
            .group_by(col(LogRecord.detected_format))
        )
        fmt_res = (await session.exec(fmt_stmt)).all()
        format_breakdown = {str(k): int(v) for k, v in fmt_res if k is not None}

        # Top MITRE techniques
        mitre_stmt = (
            select(LogRecord.mitre_technique, func.count())
            .where(
                col(LogRecord.tenant_id) == tenant_id,
                col(LogRecord.mitre_technique) != None,  # noqa: E711
            )
            .group_by(col(LogRecord.mitre_technique))
            .order_by(func.count().desc())
            .limit(10)
        )
        mitre_res = (await session.exec(mitre_stmt)).all()
        top_mitre_techniques = {str(k): int(v) for k, v in mitre_res if k is not None}

        # Top source countries
        geo_stmt = (
            select(LogRecord.geoip_country, func.count())
            .where(
                col(LogRecord.tenant_id) == tenant_id,
                col(LogRecord.geoip_country) != None,  # noqa: E711
            )
            .group_by(col(LogRecord.geoip_country))
            .order_by(func.count().desc())
            .limit(10)
        )
        geo_res = (await session.exec(geo_stmt)).all()
        top_countries = {str(k): int(v) for k, v in geo_res if k is not None}

        return TenantLogStats(
            tenant_id=tenant_id,
            total_logs=total_logs,
            threat_count=threat_count,
            duplicate_count=duplicate_count,
            severity_breakdown=severity_breakdown,
            format_breakdown=format_breakdown,
            top_mitre_techniques=top_mitre_techniques,
            top_countries=top_countries,
        )


# ==============================================================================
# 3. Global Factory Accessor
# ==============================================================================

_storage_adapter = PostgresStorageAdapter()


def get_storage_adapter() -> PostgresStorageAdapter:
    """Return singleton PostgresStorageAdapter instance."""
    return _storage_adapter
