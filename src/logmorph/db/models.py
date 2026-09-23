import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlmodel import Field, Relationship, SQLModel


class UserBase(SQLModel):
    """Base fields for User model."""
    email: str = Field(unique=True, index=True, nullable=False)
    full_name: str = Field(nullable=False)


class User(UserBase, table=True):
    """Database model for a User (acts as a Tenant)."""
    __tablename__ = "users"  # type: ignore

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    hashed_password: str = Field(nullable=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    api_keys: List["ApiKey"] = Relationship(back_populates="user", cascade_delete=True)


class ApiKeyBase(SQLModel):
    """Base fields for API Key model."""
    name: str = Field(nullable=False)


class ApiKey(ApiKeyBase, table=True):
    """Database model for an Ingestion API Key."""
    __tablename__ = "api_keys"  # type: ignore

    id: str = Field(primary_key=True, index=True, nullable=False)  # e.g., 'key_abc123'
    key_hash: str = Field(unique=True, nullable=False)
    key_prefix: str = Field(nullable=False)  # First 12 chars for display
    is_active: bool = Field(default=True, nullable=False)
    last_used_at: Optional[datetime] = Field(default=None, nullable=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    user_id: uuid.UUID = Field(foreign_key="users.id", nullable=False)
    user: User = Relationship(back_populates="api_keys")
