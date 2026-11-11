"""Aggregation router for API version 1 endpoints."""

from fastapi import APIRouter

from logmorph.api.v1.events import router as events_router
from logmorph.api.v1.ingest import router as ingest_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(ingest_router)
api_v1_router.include_router(events_router)
