"""Log Ingestion webhook endpoints protected by API Key authentication."""

import asyncio
import logging
import uuid
from collections.abc import AsyncGenerator, Callable
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from sqlalchemy import update
from sqlmodel import col
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.api.deps import get_api_key
from logmorph.db.models import ApiKey, LogSource
from logmorph.db.session import async_session_maker, get_session
from logmorph.engine.core import get_engine
from logmorph.queue.producer import LogMorphKafkaProducer, get_kafka_producer
from logmorph.schemas.errors import ErrorResponse
from logmorph.schemas.ingest import (
    BatchIngestRequest,
    BatchIngestResponse,
    IngestRequest,
    IngestResponse,
)
from logmorph.schemas.queue import RawLogMessage
from logmorph.storage.adapter import get_storage_adapter

logger = logging.getLogger(__name__)

# Bound concurrent background persistence tasks per worker to protect free-tier CPU/RAM and DB pool
_PERSIST_SEMAPHORE = asyncio.Semaphore(2)
_BATCH_CHUNK_SIZE = 50

router = APIRouter(prefix="/ingest", tags=["Log Ingestion"])


async def _update_source_metrics(
    session: AsyncSession,
    tenant_id: UUID,
    source_name: str,
    increment_by: int,
) -> None:
    """Atomically increment events_count and refresh last_seen_at for a matching LogSource."""
    if not source_name or increment_by <= 0:
        return

    now = datetime.now(UTC)
    stmt = (
        update(LogSource)
        .where(
            col(LogSource.tenant_id) == tenant_id,
            col(LogSource.name) == source_name,
            col(LogSource.is_deleted).is_(False),
        )
        .values(
            events_count=LogSource.events_count + increment_by,
            last_seen_at=now,
        )
    )
    await session.exec(stmt)  # type: ignore[call-overload]
    await session.commit()


async def _run_with_session(
    session_override: Callable[[], AsyncGenerator[AsyncSession, None]] | None,
    work: Callable[[AsyncSession], object],
) -> None:
    """Execute async DB work using a test override session if present, else async_session_maker."""
    if session_override is not None:
        async for session in session_override():
            await work(session)  # type: ignore[misc]
            break
    else:
        async with async_session_maker() as session:
            await work(session)  # type: ignore[misc]


async def _process_and_persist_single(
    raw_log: str,
    tenant_id: UUID,
    source_name: str,
    event_id: str,
    session_override: Callable[[], AsyncGenerator[AsyncSession, None]] | None = None,
) -> None:
    """Parse a single ingested log via the singleton engine and persist it to PostgreSQL."""
    async with _PERSIST_SEMAPHORE:
        try:
            engine = get_engine()
            proc_result = await engine.process_async(raw_log=raw_log, tenant_id=tenant_id)
            if not proc_result.success or proc_result.event is None:
                logger.warning(
                    "Engine failed to process event %s: %s",
                    event_id,
                    proc_result.error_message,
                )
                return

            proc_result.event.event_id = event_id
            if source_name and proc_result.event.source:
                proc_result.event.source.name = source_name

            async def _persist(session: AsyncSession) -> None:
                adapter = get_storage_adapter()
                await adapter.store_event(session, proc_result.event)  # type: ignore[arg-type]
                await _update_source_metrics(session, tenant_id, source_name, 1)

            await _run_with_session(session_override, _persist)
        except Exception:
            logger.exception("Background persistence failed for single event %s", event_id)


async def _process_and_persist_batch(
    raw_logs: list[str],
    tenant_id: UUID,
    source_name: str,
    event_ids: list[str],
    session_override: Callable[[], AsyncGenerator[AsyncSession, None]] | None = None,
) -> None:
    """Parse a batch of ingested logs in bounded chunks and persist them to PostgreSQL."""
    async with _PERSIST_SEMAPHORE:
        try:
            engine = get_engine()
            events_to_store = []

            for start in range(0, len(raw_logs), _BATCH_CHUNK_SIZE):
                chunk_logs = raw_logs[start : start + _BATCH_CHUNK_SIZE]
                chunk_ids = event_ids[start : start + _BATCH_CHUNK_SIZE]
                results = await engine.process_batch_async(raw_logs=chunk_logs, tenant_id=tenant_id)
                for res, eid in zip(results, chunk_ids, strict=True):
                    if res.success and res.event is not None:
                        res.event.event_id = eid
                        if source_name and res.event.source:
                            res.event.source.name = source_name
                        events_to_store.append(res.event)

            if not events_to_store:
                return

            async def _persist(session: AsyncSession) -> None:
                adapter = get_storage_adapter()
                stored_count = await adapter.store_batch(session, events_to_store)
                await _update_source_metrics(session, tenant_id, source_name, stored_count)

            await _run_with_session(session_override, _persist)
        except Exception:
            logger.exception("Background persistence failed for batch of %d events", len(raw_logs))


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=IngestResponse,
    responses={
        status.HTTP_202_ACCEPTED: {
            "model": IngestResponse,
            "description": "Log accepted for asynchronous ingestion and processing",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Missing, revoked, or invalid API key",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Payload schema validation error",
        },
    },
    summary="Ingest a single raw log event",
    description=(
        "Accepts a single raw log line, validates the tenant API key, "
        "generates a unique event tracking ID, dispatches to Kafka queue, and acknowledges acceptance."
    ),
)
async def ingest_single_log(
    request: Request,
    payload: IngestRequest,
    background_tasks: BackgroundTasks,
    api_key: Annotated[ApiKey, Depends(get_api_key)],
    producer: Annotated[LogMorphKafkaProducer, Depends(get_kafka_producer)],
) -> IngestResponse:
    """Ingest a single log line."""
    event_id = f"evt_{uuid.uuid4()}"
    resolved_source = (
        payload.source.strip()
        if payload.source and payload.source.strip()
        else api_key.name
    )

    message = RawLogMessage(
        event_id=event_id,
        tenant_id=api_key.user_id,
        raw_log=payload.raw_log,
        source=resolved_source,
        ingested_at=datetime.now(UTC),
    )
    await producer.send_log(message)

    session_override = request.app.dependency_overrides.get(get_session)
    background_tasks.add_task(
        _process_and_persist_single,
        payload.raw_log,
        api_key.user_id,
        resolved_source,
        event_id,
        session_override,
    )

    return IngestResponse(
        status="accepted",
        event_id=event_id,
    )


@router.post(
    "/batch",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=BatchIngestResponse,
    responses={
        status.HTTP_202_ACCEPTED: {
            "model": BatchIngestResponse,
            "description": "Log batch accepted for asynchronous ingestion and processing",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Missing, revoked, or invalid API key",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Payload schema validation error",
        },
    },
    summary="Ingest a batch of raw log events",
    description=(
        "Accepts a batch of up to 1000 raw log lines, validates the tenant API key, "
        "generates unique event tracking IDs, dispatches to Kafka queue, and acknowledges acceptance."
    ),
)
async def ingest_batch_logs(
    request: Request,
    payload: BatchIngestRequest,
    background_tasks: BackgroundTasks,
    api_key: Annotated[ApiKey, Depends(get_api_key)],
    producer: Annotated[LogMorphKafkaProducer, Depends(get_kafka_producer)],
) -> BatchIngestResponse:
    """Ingest multiple log lines in a single batch."""
    now = datetime.now(UTC)
    resolved_source = (
        payload.source.strip()
        if payload.source and payload.source.strip()
        else api_key.name
    )
    event_ids: list[str] = []
    messages: list[RawLogMessage] = []

    for raw_log in payload.logs:
        event_id = f"evt_{uuid.uuid4()}"
        event_ids.append(event_id)
        messages.append(
            RawLogMessage(
                event_id=event_id,
                tenant_id=api_key.user_id,
                raw_log=raw_log,
                source=resolved_source,
                ingested_at=now,
            )
        )

    await producer.send_batch(messages)

    session_override = request.app.dependency_overrides.get(get_session)
    background_tasks.add_task(
        _process_and_persist_batch,
        list(payload.logs),
        api_key.user_id,
        resolved_source,
        event_ids,
        session_override,
    )

    return BatchIngestResponse(
        status="accepted",
        count=len(event_ids),
        event_ids=event_ids,
    )
