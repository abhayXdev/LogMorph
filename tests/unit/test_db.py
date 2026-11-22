"""Unit tests for database models and schema relationships."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.db.models import ApiKey, LogSource, User


@pytest.mark.asyncio
async def test_create_user(async_db: AsyncSession):
    """Test creating a user."""
    user = User(
        email="test@example.com",
        full_name="Test User",
        hashed_password="fakehashedpassword123",
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    assert user.id is not None
    assert user.email == "test@example.com"
    assert user.created_at is not None


@pytest.mark.asyncio
async def test_create_api_key(async_db: AsyncSession):
    """Test creating an API key linked to a user."""
    user = User(
        email="dev@example.com",
        full_name="Dev User",
        hashed_password="fake",
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    api_key = ApiKey(
        id="key_123",
        name="Production Key",
        key_hash="hash123",
        key_prefix="lm_live_1234",
        user_id=user.id,
    )
    async_db.add(api_key)
    await async_db.commit()
    await async_db.refresh(api_key)

    assert api_key.id == "key_123"
    assert api_key.user_id == user.id
    assert api_key.is_active is True

    # Test relationship
    statement = select(User).where(User.id == user.id)
    result = await async_db.exec(statement)
    fetched_user = result.first()

    assert fetched_user is not None
    assert api_key.user_id == fetched_user.id


def test_log_source_composite_index_metadata():
    """Verify that LogSource declares the composite index on (tenant_id, created_at)."""
    index_names = [idx.name for idx in LogSource.__table__.indexes]
    assert "ix_log_sources_tenant_created_at_desc" in index_names

    composite_idx = next(
        idx for idx in LogSource.__table__.indexes if idx.name == "ix_log_sources_tenant_created_at_desc"
    )
    col_names = [c.name for c in composite_idx.columns]
    assert col_names == ["tenant_id", "created_at"]


@pytest.mark.asyncio
async def test_create_log_source_and_ordering(async_db: AsyncSession):
    """Verify multiple log sources for a tenant can be queried in descending order."""
    user = User(
        email="source_model@example.com",
        full_name="Source User",
        hashed_password="fake",
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    now = datetime.now(UTC)
    s1 = LogSource(
        id=f"src_{uuid.uuid4().hex[:12]}",
        name="Source Old",
        tenant_id=user.id,
        created_at=now - timedelta(minutes=10),
    )
    s2 = LogSource(
        id=f"src_{uuid.uuid4().hex[:12]}",
        name="Source New",
        tenant_id=user.id,
        created_at=now,
    )
    async_db.add_all([s1, s2])
    await async_db.commit()

    stmt = (
        select(LogSource)
        .where(LogSource.tenant_id == user.id)
        .order_by(LogSource.created_at.desc())
    )
    res = await async_db.exec(stmt)
    sources = res.all()

    assert len(sources) == 2
    assert sources[0].name == "Source New"
    assert sources[1].name == "Source Old"
    assert sources[0].created_at > sources[1].created_at

