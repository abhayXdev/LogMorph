import uuid
from datetime import UTC, datetime

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
    is_verified: bool = Field(default=False, nullable=False)
    email_verified_at: datetime | None = Field(default=None, nullable=True)
    verification_token_hash: str | None = Field(default=None, index=True, nullable=True)
    verification_token_expires_at: datetime | None = Field(default=None, nullable=True)
    reset_token_hash: str | None = Field(default=None, index=True, nullable=True)
    reset_token_expires_at: datetime | None = Field(default=None, nullable=True)
    token_version: int = Field(default=1, nullable=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    api_keys: list["ApiKey"] = Relationship(back_populates="user", cascade_delete=True)
    logs: list["LogRecord"] = Relationship(back_populates="user_rel", cascade_delete=True)
    sources: list["LogSource"] = Relationship(back_populates="user", cascade_delete=True)


class ApiKeyBase(SQLModel):
    """Base fields for API Key model."""

    name: str = Field(nullable=False)


class ApiKey(ApiKeyBase, table=True):
    """Database model for an Ingestion API Key."""

    __tablename__ = "api_keys"  # type: ignore

    id: str = Field(
        default_factory=lambda: f"key_{uuid.uuid4().hex[:12]}",
        primary_key=True,
        index=True,
        nullable=False,
    )
    key_hash: str = Field(unique=True, nullable=False)
    key_prefix: str = Field(nullable=False)  # First 12 chars for display
    is_active: bool = Field(default=True, nullable=False)
    last_used_at: datetime | None = Field(default=None, nullable=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    user_id: uuid.UUID = Field(foreign_key="users.id", nullable=False)
    user: User = Relationship(back_populates="api_keys")


class LogRecordBase(SQLModel):
    """Base fields for LogRecord model."""

    event_id: str = Field(index=True, nullable=False)
    timestamp: datetime = Field(index=True, nullable=False)
    raw_log: str = Field(nullable=False)
    detected_format: str = Field(index=True, nullable=False)
    severity: str = Field(default="INFORMATIONAL", index=True, nullable=False)
    action: str | None = Field(default=None, index=True, nullable=True)
    source_ip: str | None = Field(default=None, index=True, nullable=True)
    source_port: int | None = Field(default=None, nullable=True)
    destination_ip: str | None = Field(default=None, index=True, nullable=True)
    destination_port: int | None = Field(default=None, nullable=True)
    user: str | None = Field(default=None, index=True, nullable=True)
    process_name: str | None = Field(default=None, index=True, nullable=True)
    parsed_by: str = Field(default="RULE", nullable=False)
    is_duplicate: bool = Field(default=False, index=True, nullable=False)
    threat_matched: bool = Field(default=False, index=True, nullable=False)
    threat_id: str | None = Field(default=None, index=True, nullable=True)
    mitre_technique: str | None = Field(default=None, index=True, nullable=True)
    mitre_tactic: str | None = Field(default=None, index=True, nullable=True)
    geoip_country: str | None = Field(default=None, index=True, nullable=True)
    attributes_json: str = Field(default="{}", nullable=False)
    enrichment_json: str | None = Field(default=None, nullable=True)


class LogRecord(LogRecordBase, table=True):
    """Database model for storing processed UniversalLogEvents in PostgreSQL."""

    __tablename__ = "log_records"  # type: ignore

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        primary_key=True,
        index=True,
        nullable=False,
    )
    tenant_id: uuid.UUID = Field(foreign_key="users.id", index=True, nullable=False)
    ingested_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        index=True,
        nullable=False,
    )

    # Relationships
    user_rel: User = Relationship(back_populates="logs")


class LogSourceBase(SQLModel):
    """Base fields for LogSource model."""

    name: str = Field(nullable=False)
    source_type: str = Field(default="syslog", nullable=False)
    description: str | None = Field(default=None, nullable=True)
    status: str = Field(default="active", nullable=False)
    events_count: int = Field(default=0, nullable=False)
    last_seen_at: datetime | None = Field(default=None, nullable=True)


class LogSource(LogSourceBase, table=True):
    """Database model for a Log Source collector registry."""

    __tablename__ = "log_sources"  # type: ignore

    id: str = Field(
        default_factory=lambda: f"src_{uuid.uuid4().hex[:12]}",
        primary_key=True,
        index=True,
        nullable=False,
    )
    tenant_id: uuid.UUID = Field(foreign_key="users.id", index=True, nullable=False)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relationships
    user: User = Relationship(back_populates="sources")
