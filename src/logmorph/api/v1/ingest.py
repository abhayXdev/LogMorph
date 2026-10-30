"""Log Ingestion webhook endpoints protected by API Key authentication."""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, status

from logmorph.api.deps import get_api_key
from logmorph.db.models import ApiKey
from logmorph.queue.producer import LogMorphKafkaProducer, get_kafka_producer
from logmorph.schemas.errors import ErrorResponse
from logmorph.schemas.ingest import (
    BatchIngestRequest,
    BatchIngestResponse,
    IngestRequest,
    IngestResponse,
)
from logmorph.schemas.queue import RawLogMessage

router = APIRouter(prefix="/ingest", tags=["Log Ingestion"])


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
    payload: IngestRequest,
    api_key: Annotated[ApiKey, Depends(get_api_key)],
    producer: Annotated[LogMorphKafkaProducer, Depends(get_kafka_producer)],
) -> IngestResponse:
    """Ingest a single log line."""
    event_id = f"evt_{uuid.uuid4()}"

    message = RawLogMessage(
        event_id=event_id,
        tenant_id=api_key.user_id,
        raw_log=payload.raw_log,
        source=payload.source,
        ingested_at=datetime.now(UTC),
    )
    await producer.send_log(message)

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
    payload: BatchIngestRequest,
    api_key: Annotated[ApiKey, Depends(get_api_key)],
    producer: Annotated[LogMorphKafkaProducer, Depends(get_kafka_producer)],
) -> BatchIngestResponse:
    """Ingest multiple log lines in a single batch."""
    now = datetime.now(UTC)
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
                source=payload.source,
                ingested_at=now,
            )
        )

    await producer.send_batch(messages)

    return BatchIngestResponse(
        status="accepted",
        count=len(event_ids),
        event_ids=event_ids,
    )
