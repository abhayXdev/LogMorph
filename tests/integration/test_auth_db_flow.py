"""Integration tests for user registration, authentication, and JWT tenant extraction."""

from datetime import timedelta
from uuid import UUID

import jwt
import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from logmorph.db.models import User


@pytest.mark.asyncio
async def test_user_registration_and_password_flow(async_db: AsyncSession):
    """Verify that a user is created with a secure bcrypt hash and verifies cleanly."""
    plain_password = "TenantAdminPassword#2026"
    hashed = hash_password(plain_password)

    user = User(
        email="admin@cybersec-tenant.io",
        full_name="SOC Director",
        hashed_password=hashed,
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    assert user.id is not None
    # Password must never be stored in plain text
    assert user.hashed_password != plain_password
    assert user.hashed_password.startswith("$2b$")

    # Fetch from database and verify authentication
    statement = select(User).where(User.email == "admin@cybersec-tenant.io")
    result = await async_db.exec(statement)
    db_user = result.first()

    assert db_user is not None
    assert verify_password(plain_password, db_user.hashed_password) is True
    assert verify_password("WrongPassword#999", db_user.hashed_password) is False


@pytest.mark.asyncio
async def test_jwt_login_and_tenant_extraction(async_db: AsyncSession):
    """Verify full login lifecycle: credentials -> JWT -> decoded tenant lookup."""
    plain_password = "SecurePassword!987"
    user = User(
        email="analyst@soc-enterprise.com",
        full_name="Security Analyst",
        hashed_password=hash_password(plain_password),
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    # 1. Simulate authentication check
    assert verify_password(plain_password, user.hashed_password) is True

    # 2. Issue JWT Access Token
    token = create_access_token(subject=user.id, email=user.email)

    # 3. Simulate protected route authorization: decode token and lookup tenant in DB
    payload = decode_access_token(token)
    extracted_tenant_id = UUID(payload["sub"])

    tenant_stmt = select(User).where(User.id == extracted_tenant_id)
    tenant_result = await async_db.exec(tenant_stmt)
    authenticated_tenant = tenant_result.first()

    assert authenticated_tenant is not None
    assert authenticated_tenant.id == user.id
    assert authenticated_tenant.email == user.email


@pytest.mark.asyncio
async def test_duplicate_email_registration_rejected(async_db: AsyncSession):
    """Verify that database enforces unique email constraint across tenants."""
    user1 = User(
        email="duplicate@company.com",
        full_name="Tenant One",
        hashed_password=hash_password("Pass#1"),
    )
    async_db.add(user1)
    await async_db.commit()

    user2 = User(
        email="duplicate@company.com",
        full_name="Tenant Two",
        hashed_password=hash_password("Pass#2"),
    )
    async_db.add(user2)

    with pytest.raises(IntegrityError):
        await async_db.commit()


@pytest.mark.asyncio
async def test_expired_token_tenant_retrieval_rejected(async_db: AsyncSession):
    """Verify that an expired token prevents tenant authorization."""
    user = User(
        email="expired_session@tenant.com",
        full_name="Expired User",
        hashed_password=hash_password("Pass#123"),
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    expired_token = create_access_token(
        subject=user.id,
        email=user.email,
        expires_delta=timedelta(seconds=-1),
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(expired_token)
