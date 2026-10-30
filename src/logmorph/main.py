"""LogMorph FastAPI Application Entrypoint."""

import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.api.v1.router import api_v1_router
from logmorph.config import settings
from logmorph.core.exceptions import APIException
from logmorph.db.session import get_session, init_db
from logmorph.queue.producer import LogMorphKafkaProducer, get_kafka_producer, kafka_producer

logger = logging.getLogger(__name__)

# Track process startup time for uptime calculation
START_TIME: float = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan manager for startup and shutdown routines."""
    logger.info("Initializing LogMorph application...")
    try:
        await init_db()
        logger.info("Database schemas verified.")
    except Exception as e:
        logger.warning("Database auto-init skipped or encountered error: %s", e)

    # Initialize Apache Kafka producer
    try:
        await kafka_producer.start()
    except Exception as e:
        logger.warning("Kafka producer startup encountered error: %s", e)

    yield

    logger.info("Shutting down LogMorph application...")
    try:
        await kafka_producer.stop()
    except Exception as e:
        logger.warning("Kafka producer stop encountered error: %s", e)


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Universal Log Pre-processing & Normalization Engine",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception Handlers matching API_CONTRACT.md error response format
@app.exception_handler(APIException)
async def custom_api_exception_handler(request: Request, exc: APIException) -> JSONResponse:
    """Handle custom application exceptions with machine-readable error codes."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_code": exc.error_code,
            "status_code": exc.status_code,
        },
        headers=exc.headers,
    )


@app.exception_handler(HTTPException)
async def general_http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle standard HTTP exceptions formatted to API contract."""
    error_code = getattr(exc, "error_code", None)
    if not error_code:
        status_code_map: dict[int, str] = {
            400: "BAD_REQUEST",
            401: "UNAUTHORIZED",
            403: "FORBIDDEN",
            404: "NOT_FOUND",
            409: "CONFLICT",
            422: "VALIDATION_ERROR",
            429: "RATE_LIMIT_EXCEEDED",
            500: "INTERNAL_SERVER_ERROR",
        }
        error_code = status_code_map.get(exc.status_code, "HTTP_ERROR")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "error_code": error_code,
            "status_code": exc.status_code,
        },
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Handle Pydantic validation failures returning 422 with standardized error envelope."""
    errors = exc.errors()
    message = "Request validation failed"
    if errors:
        first_error = errors[0]
        field_loc = " -> ".join(str(loc) for loc in first_error.get("loc", []))
        message = f"{first_error.get('msg', 'Validation error')} ({field_loc})"

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "detail": message,
            "error_code": "VALIDATION_ERROR",
            "status_code": status.HTTP_422_UNPROCESSABLE_CONTENT,
        },
    )


# Health Check Endpoint (API Contract Section 8)
@app.get(
    "/health",
    status_code=status.HTTP_200_OK,
    tags=["System Health"],
    summary="System health status",
)
async def health_check(
    session: Annotated[AsyncSession, Depends(get_session)],
    producer: Annotated[LogMorphKafkaProducer, Depends(get_kafka_producer)],
) -> dict[str, Any]:
    """Retrieve runtime health and connected service dependencies."""
    db_status = "connected"
    try:
        await session.exec(select(1))
    except Exception as e:
        logger.warning("Database health check ping failed: %s", e)
        db_status = "disconnected"

    # Kafka health inspection
    if producer.is_connected:
        is_healthy = await producer.is_healthy()
        kafka_status = "connected" if is_healthy else "degraded"
    elif producer.fallback_queue is not None:
        kafka_status = "fallback_buffer"
    else:
        kafka_status = "disconnected"

    uptime_seconds = int(time.time() - START_TIME)
    is_healthy = db_status == "connected" and kafka_status in ("connected", "fallback_buffer")

    return {
        "status": "healthy" if is_healthy else "degraded",
        "version": "0.1.0",
        "database": db_status,
        "kafka": kafka_status,
        "redis": "unconfigured",
        "uptime_seconds": uptime_seconds,
    }


# Mount API Routers
app.include_router(api_v1_router)
