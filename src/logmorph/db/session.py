import logging
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from sqlmodel.ext.asyncio.session import AsyncSession

import logmorph.db.models  # noqa: F401  Ensure models register with SQLModel.metadata
from logmorph.config import settings

logger = logging.getLogger(__name__)

# NeonDB / PgBouncer compatibility: disable prepared statement cache when using transaction pooler
connect_args = {"statement_cache_size": 0} if "postgresql" in settings.DATABASE_URL else {}

# Create the async engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.ENVIRONMENT == "development",
    future=True,
    connect_args=connect_args,
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
            logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for getting a database session."""
    async with async_session_maker() as session:
        yield session
