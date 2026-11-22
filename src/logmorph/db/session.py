import logging
import socket
from collections.abc import AsyncGenerator
from typing import Any
from urllib.parse import urlparse

import dns.resolver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import logmorph.db.models  # noqa: F401  Ensure models register with SQLModel.metadata
from logmorph.config import settings

logger = logging.getLogger(__name__)


def _prepare_db_connection(raw_url: str) -> tuple[str, dict[str, Any]]:
    """Configure connection arguments and resolve DNS fallbacks for cloud Postgres providers."""
    connect_args: dict[str, Any] = {}
    if "postgresql" not in raw_url:
        return raw_url, connect_args

    connect_args["statement_cache_size"] = 0

    parsed = urlparse(raw_url)
    hostname = parsed.hostname
    if not hostname or "neon.tech" not in hostname:
        return raw_url, connect_args

    endpoint_id = hostname.split(".")[0]
    try:
        socket.gethostbyname(hostname)
        return raw_url, connect_args
    except Exception:
        logger.info("Local DNS lookup failed for %s. Resolving via public DNS fallback.", hostname)
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
            ans = resolver.resolve(hostname, "A")
            ip = str(ans[0])
            new_url = raw_url.replace(hostname, ip)
            connect_args["server_settings"] = {"options": f"endpoint={endpoint_id}"}
            return new_url, connect_args
        except Exception as e:
            logger.warning("Public DNS resolution fallback encountered error: %s", e)
            return raw_url, connect_args


db_url, connect_args = _prepare_db_connection(settings.DATABASE_URL)

engine_kwargs: dict[str, Any] = {
    "echo": settings.ENVIRONMENT == "development",
    "future": True,
    "connect_args": connect_args,
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

if "postgresql" in db_url:
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 5

# Create the async engine with idle resilience (pre-ping & auto-recycle)
engine = create_async_engine(
    db_url,
    **engine_kwargs,
)

# Async session factory
async_session_maker = sessionmaker(
    bind=engine,  # type: ignore
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """Initialize the database (create tables if they don't exist)."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
            # Ensure composite index on log_sources exists on pre-existing databases (FIX-P17)
            await conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_log_sources_tenant_created_at_desc "
                    "ON log_sources (tenant_id, created_at DESC)"
                )
            )
            logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for getting a database session."""
    async with async_session_maker() as session:
        yield session
