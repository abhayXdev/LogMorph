"""Integration tests for API key lifecycle, ingestion authentication, and tenant resolution."""

import pytest
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.keys import generate_api_key, hash_api_key, mask_api_key, verify_api_key
from logmorph.core.security import hash_password
from logmorph.db.models import ApiKey, User


@pytest.mark.asyncio
async def test_apikey_generation_and_db_storage(async_db: AsyncSession):
    """Verify end-to-end API key generation, hashing, and persistent storage."""
    user = User(
        email="devops@datacenter.org",
        full_name="DevOps Lead",
        hashed_password=hash_password("DevOpsPass#1"),
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    # Generate key using cryptographic utilities
    key_data = generate_api_key()

    # Store in database
    db_key = ApiKey(
        name="Palo Alto Firewall Collector",
        key_hash=key_data.key_hash,
        key_prefix=key_data.key_prefix,
        user_id=user.id,
    )
    async_db.add(db_key)
    await async_db.commit()
    await async_db.refresh(db_key)

    assert db_key.id.startswith("key_")
    assert db_key.is_active is True
    assert db_key.key_prefix == key_data.key_prefix
    assert db_key.key_hash == key_data.key_hash
    # The raw secret key must NEVER be stored in the database record
    assert key_data.raw_key != db_key.key_hash
    assert key_data.raw_key != db_key.key_prefix


@pytest.mark.asyncio
async def test_ingestion_api_key_lookup_and_tenant_resolution(async_db: AsyncSession):
    """Simulate ingestion authentication: raw key -> hash lookup -> tenant resolution."""
    user = User(
        email="siem_collector@enterprise.com",
        full_name="SIEM Pipeline",
        hashed_password=hash_password("SiemPass#2026"),
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    key_data = generate_api_key()
    api_key = ApiKey(
        name="Ingestion Key Alpha",
        key_hash=key_data.key_hash,
        key_prefix=key_data.key_prefix,
        user_id=user.id,
    )
    async_db.add(api_key)
    await async_db.commit()

    # Client sends raw API key in header (e.g. Bearer lm_live_...)
    incoming_raw_key = key_data.raw_key

    # Ingestion layer computes SHA-256 hash and queries active keys
    computed_hash = hash_api_key(incoming_raw_key)
    statement = select(ApiKey).where(
        ApiKey.key_hash == computed_hash,
        ApiKey.is_active,
    )
    result = await async_db.exec(statement)
    resolved_key = result.first()

    assert resolved_key is not None
    assert resolved_key.user_id == user.id
    assert verify_api_key(incoming_raw_key, resolved_key.key_hash) is True


@pytest.mark.asyncio
async def test_revoked_api_key_fails_ingestion(async_db: AsyncSession):
    """Verify that revoked API keys cannot authenticate incoming ingestion calls."""
    user = User(
        email="revocation_test@tenant.com",
        full_name="Security Admin",
        hashed_password=hash_password("AdminPass#99"),
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    key_data = generate_api_key()
    api_key = ApiKey(
        name="Decommissioned Key",
        key_hash=key_data.key_hash,
        key_prefix=key_data.key_prefix,
        user_id=user.id,
        is_active=False,  # Revoked key
    )
    async_db.add(api_key)
    await async_db.commit()

    # Ingestion lookup for active key must return None
    computed_hash = hash_api_key(key_data.raw_key)
    statement = select(ApiKey).where(
        ApiKey.key_hash == computed_hash,
        ApiKey.is_active,
    )
    result = await async_db.exec(statement)
    assert result.first() is None


@pytest.mark.asyncio
async def test_multi_tenant_api_key_isolation(async_db: AsyncSession):
    """Verify that API keys from Tenant A cannot access or resolve Tenant B's workspace."""
    tenant_a = User(
        email="tenant_a@cloud.io",
        full_name="Tenant A",
        hashed_password=hash_password("PassA#1"),
    )
    tenant_b = User(
        email="tenant_b@cloud.io",
        full_name="Tenant B",
        hashed_password=hash_password("PassB#2"),
    )
    async_db.add_all([tenant_a, tenant_b])
    await async_db.commit()
    await async_db.refresh(tenant_a)
    await async_db.refresh(tenant_b)

    key_a = generate_api_key()
    key_b = generate_api_key()

    async_db.add_all([
        ApiKey(
            name="Key A",
            key_hash=key_a.key_hash,
            key_prefix=key_a.key_prefix,
            user_id=tenant_a.id,
        ),
        ApiKey(
            name="Key B",
            key_hash=key_b.key_hash,
            key_prefix=key_b.key_prefix,
            user_id=tenant_b.id,
        ),
    ])
    await async_db.commit()

    # Query Tenant A's keys
    stmt_a = select(ApiKey).where(ApiKey.user_id == tenant_a.id)
    keys_a = (await async_db.exec(stmt_a)).all()

    assert len(keys_a) == 1
    assert keys_a[0].key_prefix == key_a.key_prefix
    assert mask_api_key(keys_a[0].key_prefix) == f"{key_a.key_prefix}****"

    # Verify Key A never resolves to Tenant B
    resolved_a = (
        await async_db.exec(
            select(ApiKey).where(ApiKey.key_hash == hash_api_key(key_a.raw_key))
        )
    ).first()
    assert resolved_a is not None
    assert resolved_a.user_id != tenant_b.id
    assert resolved_a.user_id == tenant_a.id
