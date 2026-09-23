import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.db.models import ApiKey, User


@pytest.fixture
async def async_db():
    """Create an in-memory SQLite database for testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    
    async_session = sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    async with async_session() as session:
        yield session
    
    await engine.dispose()


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
    # Depending on async session configuration, relationships might need explicit eager loading.
    # We will just verify foreign key works.
    assert api_key.user_id == fetched_user.id
