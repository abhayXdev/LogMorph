"""Log source collector management endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.api.deps import get_current_tenant
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
        .where(LogSource.tenant_id == user.id)
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
    )
    res = await session.exec(stmt)
    source = res.first()

    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Source not found",
        )

    await session.delete(source)
    await session.commit()

    return LogSourceDeleteResponse(
        message="Source deleted successfully",
        source_id=source_id,
    )
