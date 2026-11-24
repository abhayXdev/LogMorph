"""Uvicorn server configuration factory (FIX-P13).

Provides standardized production and development Uvicorn configurations,
ensuring keep-alive timeouts (30s) and request limits (10000) are enforced
to prevent premature socket resets after heavy payloads and worker memory leaks.
"""

from __future__ import annotations

import uvicorn

from logmorph.config import settings


def get_uvicorn_config(
    app: str = "logmorph.main:app",
    host: str = "0.0.0.0",
    port: int = 8000,
    workers: int = 1,
    reload: bool = False,
    timeout_keep_alive: int | None = None,
    limit_max_requests: int | None = None,
) -> uvicorn.Config:
    """Build standardized Uvicorn Config with production keep-alive and recycling guards."""
    return uvicorn.Config(
        app=app,
        host=host,
        port=port,
        workers=workers,
        reload=reload,
        proxy_headers=True,
        timeout_keep_alive=timeout_keep_alive
        if timeout_keep_alive is not None
        else settings.UVICORN_KEEP_ALIVE_TIMEOUT,
        limit_max_requests=limit_max_requests
        if limit_max_requests is not None
        else settings.UVICORN_MAX_REQUESTS,
    )
