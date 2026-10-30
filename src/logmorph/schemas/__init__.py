"""API schema definitions for LogMorph."""

from logmorph.schemas.detection import DetectionResult
from logmorph.schemas.errors import ErrorResponse
from logmorph.schemas.ingest import (
    BatchIngestRequest,
    BatchIngestResponse,
    IngestRequest,
    IngestResponse,
)
from logmorph.schemas.queue import RawLogMessage

__all__ = [
    "BatchIngestRequest",
    "BatchIngestResponse",
    "DetectionResult",
    "ErrorResponse",
    "IngestRequest",
    "IngestResponse",
    "RawLogMessage",
]
