"""Aggregation router for API version 1 endpoints."""

from fastapi import APIRouter

from logmorph.api.v1.events import router as events_router
from logmorph.api.v1.ingest import router as ingest_router
from logmorph.api.v1.keys import router as keys_router
from logmorph.api.v1.sandbox import router as sandbox_router
from logmorph.api.v1.sources import router as sources_router
from logmorph.api.v1.stats import router as stats_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(ingest_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(keys_router)
api_v1_router.include_router(sandbox_router)
api_v1_router.include_router(stats_router)
api_v1_router.include_router(sources_router)
