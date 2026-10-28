"""Shared test fixtures for LogMorph test suite."""

from collections.abc import AsyncGenerator

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import logmorph.db.models  # noqa: F401 Ensure models are registered


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
