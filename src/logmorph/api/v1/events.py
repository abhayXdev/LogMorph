"""Tenant-isolated log event search, retrieval, and lifecycle endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.api.deps import get_current_tenant
from logmorph.db.models import User
from logmorph.db.session import get_session
from logmorph.domain.uls import LogFormatEnum, SeverityEnum
from logmorph.schemas.errors import ErrorResponse
from logmorph.schemas.events import (
    EventDeleteResponse,
    EventDetailResponse,
    EventSearchResponse,
    EventsPagination,
    PaginatedEventsResponse,
)
from logmorph.schemas.storage import LogQueryFilter
from logmorph.storage.adapter import PostgresStorageAdapter, get_storage_adapter

router = APIRouter(prefix="/events", tags=["Log Events & Search"])


@router.get(
    "",
    response_model=PaginatedEventsResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {
            "model": PaginatedEventsResponse,
            "description": "Paginated list of tenant log events matching filter criteria",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Missing or invalid authentication token",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Validation error in query parameters",
        },
    },
    summary="List and filter processed log events",
    description="Retrieve paginated log events strictly scoped to the authenticated tenant.",
)
async def list_events(
    page: Annotated[int, Query(ge=1, description="Page number starting at 1")] = 1,
    limit: Annotated[
        int, Query(ge=1, le=100, description="Number of events per page (max 100)")
    ] = 25,
    severity: Annotated[
        str | None,
        Query(description="Filter by severity level (e.g. CRITICAL, ERROR)"),
    ] = None,
    format: Annotated[
        str | None,
        Query(description="Filter by detected format (e.g. SYSLOG, JSON, CEF)"),
    ] = None,
    source: Annotated[
        str | None,
        Query(description="Filter by source endpoint or IP"),
    ] = None,
    start_time: Annotated[
        datetime | None,
        Query(alias="from", description="Start of temporal range"),
    ] = None,
    end_time: Annotated[
        datetime | None,
        Query(alias="to", description="End of temporal range"),
    ] = None,
    threat_matched: Annotated[
        bool | None,
        Query(description="Filter by presence of threat intelligence match"),
    ] = None,
    mitre_technique: Annotated[
        str | None,
        Query(description="Filter by MITRE ATT&CK technique ID"),
    ] = None,
    q: Annotated[
        str | None,
        Query(description="Optional text search query across message and attributes"),
    ] = None,
    user: Annotated[User, Depends(get_current_tenant)] = None,  # type: ignore[assignment]
    session: Annotated[AsyncSession, Depends(get_session)] = None,  # type: ignore[assignment]
    adapter: Annotated[PostgresStorageAdapter, Depends(get_storage_adapter)] = None,  # type: ignore[assignment]
) -> PaginatedEventsResponse:
    """List log events with deterministic pagination and multi-vector filtering."""
    offset = (page - 1) * limit

    sev_enum: SeverityEnum | None = None
    if severity:
        try:
            sev_enum = SeverityEnum(severity.upper())
        except ValueError:
            sev_enum = None

    fmt_enum: LogFormatEnum | None = None
    if format:
        try:
            fmt_enum = LogFormatEnum(format.upper())
        except ValueError:
            fmt_enum = None

    query_filter = LogQueryFilter(
        start_time=start_time,
        end_time=end_time,
        severity=sev_enum,
        detected_format=fmt_enum,
        source_ip=source,
        threat_matched=threat_matched,
        mitre_technique=mitre_technique,
        search_term=q,
        limit=limit,
        offset=offset,
    )

    items, total = await adapter.query_event_items(
        session=session,
        tenant_id=user.id,
        filter_params=query_filter,
    )

    total_pages = (total + limit - 1) // limit if total > 0 else 0

    return PaginatedEventsResponse(
        events=items,
        pagination=EventsPagination(
            page=page,
            limit=limit,
            total=total,
            total_pages=total_pages,
        ),
    )


@router.get(
    "/search",
    response_model=EventSearchResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {
            "model": EventSearchResponse,
            "description": "Full-text search results with relevance scores",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Missing or invalid authentication token",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Missing or invalid search query",
        },
    },
    summary="Full-text search across log events",
    description="Search across raw log contents, actions, users, and endpoints with relevance scoring.",
)
async def search_events(
    q: Annotated[str, Query(min_length=1, description="Search query string")],
    limit: Annotated[
        int, Query(ge=1, le=100, description="Maximum number of search results to return")
    ] = 20,
    user: Annotated[User, Depends(get_current_tenant)] = None,  # type: ignore[assignment]
    session: Annotated[AsyncSession, Depends(get_session)] = None,  # type: ignore[assignment]
    adapter: Annotated[PostgresStorageAdapter, Depends(get_storage_adapter)] = None,  # type: ignore[assignment]
) -> EventSearchResponse:
    """Full-text search scoped strictly to the calling tenant."""
    results, total = await adapter.search_events(
        session=session,
        tenant_id=user.id,
        query_str=q,
        limit=limit,
    )

    return EventSearchResponse(
        query=q,
        results=results,
        total=total,
    )


@router.get(
    "/{event_id}",
    response_model=EventDetailResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {
            "model": EventDetailResponse,
            "description": "Detailed event representation",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Missing or invalid authentication token",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Event not found or belongs to another tenant",
        },
    },
    summary="Get full detail of a single event",
    description="Retrieve comprehensive normalized fields, enrichment metadata, and raw attributes.",
)
async def get_event_by_id(
    event_id: str,
    user: Annotated[User, Depends(get_current_tenant)] = None,  # type: ignore[assignment]
    session: Annotated[AsyncSession, Depends(get_session)] = None,  # type: ignore[assignment]
    adapter: Annotated[PostgresStorageAdapter, Depends(get_storage_adapter)] = None,  # type: ignore[assignment]
) -> EventDetailResponse:
    """Fetch an individual log record ensuring strict tenant boundary."""
    event = await adapter.get_event_detail(
        session=session,
        tenant_id=user.id,
        event_id=event_id,
    )

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )

    return event


@router.delete(
    "/{event_id}",
    response_model=EventDeleteResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {
            "model": EventDeleteResponse,
            "description": "Confirmation of event deletion",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Missing or invalid authentication token",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Event not found or belongs to another tenant",
        },
    },
    summary="Delete a single log event",
    description="Safely removes an event owned by the authenticated tenant.",
)
async def delete_event_by_id(
    event_id: str,
    user: Annotated[User, Depends(get_current_tenant)] = None,  # type: ignore[assignment]
    session: Annotated[AsyncSession, Depends(get_session)] = None,  # type: ignore[assignment]
    adapter: Annotated[PostgresStorageAdapter, Depends(get_storage_adapter)] = None,  # type: ignore[assignment]
) -> EventDeleteResponse:
    """Delete a log event strictly bounded by tenant ownership."""
    deleted = await adapter.delete_log(
        session=session,
        tenant_id=user.id,
        event_id=event_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )

    return EventDeleteResponse(
        message="Event deleted successfully",
        event_id=event_id,
    )
