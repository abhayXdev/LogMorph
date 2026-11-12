"""Integration tests for user registration, authentication, verification, and password lifecycle."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.email import get_email_service, hash_token
from logmorph.core.security import create_access_token, hash_password
from logmorph.db.models import User


@pytest.mark.asyncio
async def test_signup_success_and_email_dispatched(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify signup creates user in unverified state and dispatches verification email."""
    email_service = get_email_service()
    email_service.sent_emails.clear()

    payload = {
        "email": "alice@logmorph.io",
        "password": "SecurePassword#2026",
        "full_name": "Alice SOC Analyst",
    }
    response = await async_client.post("/auth/signup", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["email"] == "alice@logmorph.io"
    assert data["full_name"] == "Alice SOC Analyst"
    assert data["is_verified"] is False
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Verify user exists in database
    stmt = select(User).where(User.email == "alice@logmorph.io")
    user = (await async_db.exec(stmt)).first()
    assert user is not None
    assert user.is_verified is False
    assert user.verification_token_hash is not None

    # Verify verification email was recorded
    assert len(email_service.sent_emails) == 1
    sent = email_service.sent_emails[0]
    assert sent["to"] == "alice@logmorph.io"
    assert "Verify your LogMorph account" in sent["subject"]


@pytest.mark.asyncio
async def test_signup_duplicate_email_conflict_409(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify registering with an existing email returns 409 Conflict."""
    existing_user = User(
        email="duplicate@logmorph.io",
        full_name="Existing User",
        hashed_password=hash_password("Pass#1234"),
    )
    async_db.add(existing_user)
    await async_db.commit()

    payload = {
        "email": "duplicate@logmorph.io",
        "password": "NewPassword#2026",
        "full_name": "Second User",
    }
    response = await async_client.post("/auth/signup", json=payload)
    assert response.status_code == 409
    assert response.json()["error_code"] == "CONFLICT"


@pytest.mark.asyncio
async def test_login_success(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify logging in with valid credentials returns JWT token."""
    plain_pw = "ValidP@ssword2026"
    user = User(
        email="bob@logmorph.io",
        full_name="Bob Engineer",
        hashed_password=hash_password(plain_pw),
        is_verified=True,
    )
    async_db.add(user)
    await async_db.commit()

    payload = {"email": "bob@logmorph.io", "password": plain_pw}
    response = await async_client.post("/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["email"] == "bob@logmorph.io"


@pytest.mark.asyncio
async def test_login_unverified_user_blocked_403(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify that unverified users are blocked from logging in with 403 Forbidden."""
    plain_pw = "ValidP@ssword2026"
    user = User(
        email="unverified_bob@logmorph.io",
        full_name="Unverified Bob",
        hashed_password=hash_password(plain_pw),
        is_verified=False,
    )
    async_db.add(user)
    await async_db.commit()

    payload = {"email": "unverified_bob@logmorph.io", "password": plain_pw}
    response = await async_client.post("/auth/login", json=payload)
    assert response.status_code == 403
    assert "not verified" in response.json()["detail"]


@pytest.mark.asyncio
async def test_login_wrong_password_fails_401(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify logging in with incorrect password returns 401 Unauthorized."""
    user = User(
        email="charlie@logmorph.io",
        full_name="Charlie Analyst",
        hashed_password=hash_password("RealPassword#123"),
    )
    async_db.add(user)
    await async_db.commit()

    payload = {"email": "charlie@logmorph.io", "password": "WrongPassword#999"}
    response = await async_client.post("/auth/login", json=payload)
    assert response.status_code == 401
    assert response.json()["error_code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_get_me_profile(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify GET /auth/me returns the authenticated tenant's profile."""
    user = User(
        email="me_test@logmorph.io",
        full_name="Me Tester",
        hashed_password=hash_password("Pass#123"),
        is_verified=True,
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    token = create_access_token(subject=user.id, email=user.email)
    headers = {"Authorization": f"Bearer {token}"}

    response = await async_client.get("/auth/me", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "me_test@logmorph.io"
    assert data["full_name"] == "Me Tester"
    assert data["is_verified"] is True


@pytest.mark.asyncio
async def test_verify_email_flow(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify submitting a valid verification token marks the account as verified."""
    raw_token = "valid_crypto_verification_token_123456"
    token_hash = hash_token(raw_token)
    expires_at = datetime.now(UTC) + timedelta(hours=24)

    user = User(
        email="verify_test@logmorph.io",
        full_name="Verify Tester",
        hashed_password=hash_password("Pass#123"),
        is_verified=False,
        verification_token_hash=token_hash,
        verification_token_expires_at=expires_at,
    )
    async_db.add(user)
    await async_db.commit()

    # Submit verification
    response = await async_client.post(
        "/auth/verify-email",
        json={"token": raw_token},
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Email verified successfully"

    # Verify user record updated in database
    await async_db.refresh(user)
    assert user.is_verified is True
    assert user.verification_token_hash is None
    assert user.email_verified_at is not None

    # Re-submitting the same token must fail with 400
    repeat_response = await async_client.post(
        "/auth/verify-email",
        json={"token": raw_token},
    )
    assert repeat_response.status_code == 400


@pytest.mark.asyncio
async def test_resend_verification_email(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify resending verification email generates a new token and sends email."""
    email_service = get_email_service()
    email_service.sent_emails.clear()

    user = User(
        email="unverified_resend@logmorph.io",
        full_name="Resend Tester",
        hashed_password=hash_password("Pass#123"),
        is_verified=False,
    )
    async_db.add(user)
    await async_db.commit()

    response = await async_client.post(
        "/auth/resend-verification",
        json={"email": "unverified_resend@logmorph.io"},
    )
    assert response.status_code == 200
    assert len(email_service.sent_emails) == 1
    assert email_service.sent_emails[0]["to"] == "unverified_resend@logmorph.io"


@pytest.mark.asyncio
async def test_forgot_password_anti_enumeration(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify forgot-password returns identical 200 response for existing and non-existing emails."""
    email_service = get_email_service()
    email_service.sent_emails.clear()

    user = User(
        email="existing_user@logmorph.io",
        full_name="Existing User",
        hashed_password=hash_password("Pass#123"),
    )
    async_db.add(user)
    await async_db.commit()

    # 1. Existing user -> returns 200 and sends email
    resp1 = await async_client.post(
        "/auth/forgot-password",
        json={"email": "existing_user@logmorph.io"},
    )
    assert resp1.status_code == 200
    assert "If an account with that email exists" in resp1.json()["message"]
    assert len(email_service.sent_emails) == 1

    # 2. Non-existent user -> returns identical 200 but sends no email
    resp2 = await async_client.post(
        "/auth/forgot-password",
        json={"email": "nonexistent@logmorph.io"},
    )
    assert resp2.status_code == 200
    assert resp2.json()["message"] == resp1.json()["message"]
    assert len(email_service.sent_emails) == 1  # No new email sent


@pytest.mark.asyncio
async def test_reset_password_success(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify resetting password with recovery token updates password and increments token_version."""
    raw_token = "valid_password_reset_token_12345678"
    token_hash = hash_token(raw_token)
    expires_at = datetime.now(UTC) + timedelta(minutes=15)

    user = User(
        email="reset_me@logmorph.io",
        full_name="Reset User",
        hashed_password=hash_password("OldPassword#2025"),
        reset_token_hash=token_hash,
        reset_token_expires_at=expires_at,
        token_version=1,
        is_verified=True,
    )
    async_db.add(user)
    await async_db.commit()

    # Reset password
    new_pw = "BrandNewPassword#2026"
    response = await async_client.post(
        "/auth/reset-password",
        json={"token": raw_token, "new_password": new_pw},
    )
    assert response.status_code == 200
    assert "Password has been reset successfully" in response.json()["message"]

    # Verify user record
    await async_db.refresh(user)
    assert user.reset_token_hash is None
    assert user.token_version == 2

    # Verify user can log in with new password
    login_resp = await async_client.post(
        "/auth/login",
        json={"email": "reset_me@logmorph.io", "password": new_pw},
    )
    assert login_resp.status_code == 200

    # Old password must fail
    old_login_resp = await async_client.post(
        "/auth/login",
        json={"email": "reset_me@logmorph.io", "password": "OldPassword#2025"},
    )
    assert old_login_resp.status_code == 401


@pytest.mark.asyncio
async def test_change_password_flow(
    async_client: AsyncClient,
    async_db: AsyncSession,
):
    """Verify in-app password change for logged-in user."""
    old_pw = "CurrentPassword#123"
    user = User(
        email="changer@logmorph.io",
        full_name="Changer User",
        hashed_password=hash_password(old_pw),
        is_verified=True,
    )
    async_db.add(user)
    await async_db.commit()
    await async_db.refresh(user)

    token = create_access_token(subject=user.id, email=user.email)
    headers = {"Authorization": f"Bearer {token}"}

    # Wrong current password fails 401
    fail_resp = await async_client.post(
        "/auth/change-password",
        json={"current_password": "WrongPassword", "new_password": "NewPassword#12345"},
        headers=headers,
    )
    assert fail_resp.status_code == 401

    # Correct password succeeds 200
    success_resp = await async_client.post(
        "/auth/change-password",
        json={"current_password": old_pw, "new_password": "NewPassword#12345"},
        headers=headers,
    )
    assert success_resp.status_code == 200
    assert success_resp.json()["message"] == "Password updated successfully"
