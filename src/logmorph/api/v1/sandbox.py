"""Sandbox live log parsing playground endpoint."""

from __future__ import annotations

import time
import uuid

from fastapi import APIRouter, HTTPException, Request, status

from logmorph.core.rate_limit import limiter
from logmorph.engine.core import get_engine
from logmorph.schemas.sandbox import SandboxParseRequest, SandboxParseResponse
from logmorph.storage.adapter import log_event_to_record, record_to_event_item

router = APIRouter(prefix="/sandbox", tags=["Sandbox / Live Demo"])


@router.post(
    "/parse",
    status_code=status.HTTP_200_OK,
    response_model=SandboxParseResponse,
    summary="Parse a raw log line interactively",
    description="Test arbitrary log lines through the 3-Tier Adaptive Cascade and Enrichment engine.",
)
@limiter.limit("30/minute")
async def parse_sandbox_log(
    request: Request,
    payload: SandboxParseRequest,
) -> SandboxParseResponse:
    """Execute live parsing cascade on candidate log string without storing."""
    engine = get_engine()
    temp_tenant_id = uuid.uuid4()

    start_time = time.perf_counter()
    res = await engine.process_async(
        raw_log=payload.raw_log,
        tenant_id=temp_tenant_id,
    )
    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    if res.event is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=res.error_message or "Failed to process log line",
        )

    record = log_event_to_record(res.event)
    event_item = record_to_event_item(record)

    fmt_str = (
        res.format_detected.value
        if res.format_detected
        else "UNSTRUCTURED"
    )
    tier_str = (
        res.parsed_by.value
        if res.parsed_by
        else "FALLBACK"
    )

    return SandboxParseResponse(
        detected_format=fmt_str,
        parsed_by=tier_str,
        event=event_item,
        processing_ms=elapsed_ms,
    )
