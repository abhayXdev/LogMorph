"""Middleware for decompressing incoming gzip request bodies to support WAF-evading log ingestion."""

from __future__ import annotations

import gzip
import io
import logging

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Maximum decompressed payload size: 10MB safety ceiling against decompression bombs
MAX_DECOMPRESSED_BYTES = 10 * 1024 * 1024


def safe_gzip_decompress(data: bytes, max_size: int = MAX_DECOMPRESSED_BYTES) -> bytes:
    """Decompress gzip bytes with bounded memory allocation to prevent zip bomb attacks."""
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
        chunks: list[bytes] = []
        total_size = 0
        while True:
            chunk = gz.read(64 * 1024)  # 64KB chunks
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > max_size:
                raise ValueError(
                    f"Decompressed payload exceeded maximum limit of {max_size} bytes"
                )
            chunks.append(chunk)
        return b"".join(chunks)


class GzipRequestMiddleware(BaseHTTPMiddleware):
    """Decompress gzip-encoded HTTP request bodies.

    Allows telemetry agents and collectors to send gzip-compressed logs
    ('Content-Encoding: gzip'), which prevents Cloudflare/Render edge WAFs
    from incorrectly blocking security logs that contain directory traversal
    attack signatures (e.g. '../../etc/passwd').
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        content_encoding = request.headers.get("content-encoding", "").lower()

        if "gzip" in content_encoding:
            try:
                raw_body = await request.body()
                if raw_body:
                    decompressed = safe_gzip_decompress(raw_body)
                    request._body = decompressed

                    async def receive() -> dict[str, object]:
                        return {
                            "type": "http.request",
                            "body": decompressed,
                            "more_body": False,
                        }

                    request._receive = receive
            except ValueError as e:
                logger.warning("Gzip payload rejected: %s", e)
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "detail": str(e),
                        "error_code": "PAYLOAD_TOO_LARGE",
                        "status_code": status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    },
                )
            except Exception as e:
                logger.warning("Failed to decompress gzip request body: %s", e)
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "detail": f"Malformed gzip request body: {e}",
                        "error_code": "GZIP_DECODE_ERROR",
                        "status_code": status.HTTP_400_BAD_REQUEST,
                    },
                )

        return await call_next(request)
