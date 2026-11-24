"""Unit tests for database session engine configuration and connection pooling."""

import pytest

from logmorph.db.session import _prepare_db_connection, engine, init_db


def test_engine_pool_pre_ping_and_recycle_configured():
    """Verify that pool_pre_ping and pool_recycle are active on the application engine."""
    # Ensure pool_pre_ping is enabled to prevent stale idle socket disconnects
    assert getattr(engine.pool, "_pre_ping", False) is True, (
        "Engine pool must have pool_pre_ping=True to discard dead connections automatically."
    )
    # Ensure pool_recycle is set to 300s (5 minutes) matching NeonDB serverless compute suspension
    assert getattr(engine.pool, "_recycle", None) == 300, (
        "Engine pool must have pool_recycle=300 to refresh idle sockets proactively."
    )


def test_prepare_db_connection_sqlite():
    """Verify that SQLite connection URLs pass through unchanged without server_settings."""
    url, connect_args = _prepare_db_connection("sqlite+aiosqlite:///:memory:")
    assert url == "sqlite+aiosqlite:///:memory:"
    assert connect_args == {}


def test_prepare_db_connection_generic_postgres():
    """Verify generic PostgreSQL connection URL sets statement_cache_size=0 for asyncpg."""
    url, connect_args = _prepare_db_connection("postgresql+asyncpg://user:pass@localhost:5432/testdb")
    assert url == "postgresql+asyncpg://user:pass@localhost:5432/testdb"
    assert connect_args.get("statement_cache_size") == 0


@pytest.mark.asyncio
async def test_init_db_executes_idempotently():
    """Verify init_db initializes schemas without error across multiple invocations."""
    await init_db()
    # Second invocation should be completely idempotent and safe
    await init_db()

