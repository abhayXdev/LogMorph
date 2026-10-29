"""Shared test fixtures for LogMorph test suite."""

from collections.abc import AsyncGenerator

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import logmorph.db.models  # noqa: F401 Ensure models are registered
from logmorph.db.session import get_session
from logmorph.main import app


@pytest.fixture
async def async_db() -> AsyncGenerator[AsyncSession, None]:
    """Create an isolated in-memory SQLite database for each test function."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    async_session = sessionmaker(
        bind=engine,  # type: ignore[call-overload]
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
async def async_client(async_db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Provide an HTTPX AsyncClient configured with an in-memory database override."""

    async def _override_get_session() -> AsyncGenerator[AsyncSession, None]:
        yield async_db

    app.dependency_overrides[get_session] = _override_get_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()
