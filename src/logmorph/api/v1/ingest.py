"""Log Ingestion webhook endpoints protected by API Key authentication."""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from logmorph.api.deps import get_api_key
from logmorph.db.models import ApiKey
from logmorph.schemas.errors import ErrorResponse
from logmorph.schemas.ingest import (
    BatchIngestRequest,
    BatchIngestResponse,
    IngestRequest,
    IngestResponse,
)

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
        "generates a unique event tracking ID, and acknowledges acceptance."
    ),
)
async def ingest_single_log(
    payload: IngestRequest,
    api_key: Annotated[ApiKey, Depends(get_api_key)],
) -> IngestResponse:
    """Ingest a single log line."""
    event_id = f"evt_{uuid.uuid4()}"

    # In D2-T2, this is where Kafka producer queueing will be wired:
    # await kafka_producer.send(
    #     topic=settings.KAFKA_TOPIC_RAW_LOGS,
    #     key=str(api_key.user_id).encode(),
    #     value={"event_id": event_id, "tenant_id": str(api_key.user_id), ...}
    # )

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
        "generates unique event tracking IDs, and acknowledges acceptance."
    ),
)
async def ingest_batch_logs(
    payload: BatchIngestRequest,
    api_key: Annotated[ApiKey, Depends(get_api_key)],
) -> BatchIngestResponse:
    """Ingest multiple log lines in a single batch."""
    event_ids = [f"evt_{uuid.uuid4()}" for _ in payload.logs]

    # In D2-T2, batch streaming to Kafka will be dispatched here

    return BatchIngestResponse(
        status="accepted",
        count=len(event_ids),
        event_ids=event_ids,
    )
