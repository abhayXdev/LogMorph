"""Log source collector management endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.api.deps import get_current_tenant
from logmorph.core.probe_limiter import record_404_and_check_limit
from logmorph.core.telemetry import log_idor_probe
from logmorph.db.models import LogSource, User
from logmorph.db.session import get_session
from logmorph.schemas.errors import ErrorResponse
from logmorph.schemas.sources import (
    LogSourceCreateRequest,
    LogSourceDeleteResponse,
    LogSourceResponse,
    LogSourcesListResponse,
)

router = APIRouter(prefix="/sources", tags=["Log Sources"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=LogSourceResponse,
    responses={
        status.HTTP_201_CREATED: {
            "model": LogSourceResponse,
            "description": "Log source created successfully",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required",
        },
    },
    summary="Register a new log source",
)
async def create_source(
    payload: LogSourceCreateRequest,
    user: Annotated[User, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> LogSourceResponse:
    """Register a new log collector source for the tenant."""
    source = LogSource(
        name=payload.name.strip(),
        source_type=payload.type.strip().upper(),
        description=payload.description.strip() if payload.description else None,
        status="active",
        events_count=0,
        tenant_id=user.id,
    )
    session.add(source)
    await session.commit()
    await session.refresh(source)

    return LogSourceResponse(
        id=source.id,
        name=source.name,
        type=source.source_type,
        description=source.description,
        status=source.status,
        events_count=source.events_count,
        last_seen_at=source.last_seen_at,
        created_at=source.created_at,
    )


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    response_model=LogSourcesListResponse,
    summary="List all configured log sources",
)
async def list_sources(
    user: Annotated[User, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> LogSourcesListResponse:
    """Retrieve all log collector sources configured for the calling tenant."""
    stmt = (
        select(LogSource)
        .where(
            LogSource.tenant_id == user.id,
            LogSource.is_deleted.is_(False),
        )
        .order_by(LogSource.created_at.desc())  # type: ignore[attr-defined]
    )
    res = await session.exec(stmt)
    sources = res.all()

    items = [
        LogSourceResponse(
            id=s.id,
            name=s.name,
            type=s.source_type,
            description=s.description,
            status=s.status,
            events_count=s.events_count,
            last_seen_at=s.last_seen_at,
            created_at=s.created_at,
        )
        for s in sources
    ]

    return LogSourcesListResponse(
        sources=items,
        total=len(items),
    )


@router.delete(
    "/{source_id}",
    status_code=status.HTTP_200_OK,
    response_model=LogSourceDeleteResponse,
    responses={
        status.HTTP_200_OK: {
            "model": LogSourceDeleteResponse,
            "description": "Source deleted successfully",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Source not found",
        },
    },
    summary="Delete a log source",
)
async def delete_source(
    source_id: str,
    user: Annotated[User, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> LogSourceDeleteResponse:
    """Delete a log source ensuring tenant ownership."""
    stmt = select(LogSource).where(
        LogSource.id == source_id,
        LogSource.tenant_id == user.id,
        LogSource.is_deleted.is_(False),
    )
    res = await session.exec(stmt)
    source = res.first()

    if not source:
        # Check if source exists globally under another tenant (IDOR probe telemetry - FIX-P14)
        global_stmt = select(LogSource).where(
            LogSource.id == source_id,
            LogSource.is_deleted.is_(False),
        )
        global_source = (await session.exec(global_stmt)).first()
        if global_source and global_source.tenant_id != user.id:
            log_idor_probe(
                resource_type="LogSource",
                resource_id=source_id,
                requesting_tenant_id=user.id,
                actual_owner_tenant_id=global_source.tenant_id,
                action="DELETE",
            )
        # Track 404 probe cascade and throttle if > 20/min (FIX-P15)
        await record_404_and_check_limit(tenant_id=user.id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source not found",
        )

    source.is_deleted = True
    source.status = "archived"
    source.deleted_at = datetime.now(UTC)
    session.add(source)
    await session.commit()

    return LogSourceDeleteResponse(
        message="Source deleted successfully",
        source_id=source_id,
    )
