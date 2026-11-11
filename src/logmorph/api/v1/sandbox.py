"""Sandbox live log parsing playground endpoint."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, status

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
async def parse_sandbox_log(
    payload: SandboxParseRequest,
) -> SandboxParseResponse:
    """Execute live parsing cascade on candidate log string without storing."""
    engine = get_engine()
    temp_tenant_id = uuid.uuid4()

    res = await engine.process_async(
        raw_log=payload.raw_log,
        tenant_id=temp_tenant_id,
    )

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
    )
