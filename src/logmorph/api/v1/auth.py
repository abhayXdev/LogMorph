"""Authentication, account verification, and password management endpoints."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.api.deps import get_current_tenant
from logmorph.core.email import get_email_service, hash_token
from logmorph.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from logmorph.db.models import User
from logmorph.db.session import get_session
from logmorph.schemas.auth import (
    AuthResponse,
    ChangePasswordRequest,
    ChangePasswordResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResendVerificationRequest,
    ResetPasswordRequest,
    ResetPasswordResponse,
    UserLoginRequest,
    UserProfileResponse,
    UserSignupRequest,
    VerifyEmailRequest,
    VerifyEmailResponse,
)
from logmorph.schemas.errors import ErrorResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/signup",
    status_code=status.HTTP_201_CREATED,
    response_model=AuthResponse,
    responses={
        status.HTTP_201_CREATED: {
            "model": AuthResponse,
            "description": "User created successfully",
        },
        status.HTTP_409_CONFLICT: {
            "model": ErrorResponse,
            "description": "Email already registered",
        },
        status.HTTP_422_UNPROCESSABLE_CONTENT: {
            "model": ErrorResponse,
            "description": "Validation error",
        },
    },
    summary="Register a new user account",
)
async def signup(
    payload: UserSignupRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AuthResponse:
    """Create a new user account and dispatch verification email."""
    # 1. Check if email already registered
    existing_stmt = select(User).where(User.email == payload.email.lower().strip())
    existing_res = await session.exec(existing_stmt)
    existing_user = existing_res.first()
    if existing_user:
        if not existing_user.is_verified:
            # Resend verification email for unverified user
            raw_token = secrets.token_urlsafe(32)
            existing_user.verification_token_hash = hash_token(raw_token)
            existing_user.verification_token_expires_at = datetime.now(UTC) + timedelta(hours=24)
            session.add(existing_user)
            await session.commit()

            email_service = get_email_service()
            await email_service.send_verification_email(
                to_email=existing_user.email,
                full_name=existing_user.full_name,
                raw_token=raw_token,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An unverified account with this email already exists. A fresh verification link has been sent to your email.",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # 2. Generate email verification token
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    expires_at = datetime.now(UTC) + timedelta(hours=24)

    # 3. Create user record
    user = User(
        email=payload.email.lower().strip(),
        full_name=payload.full_name.strip(),
        hashed_password=hash_password(payload.password),
        is_verified=False,
        verification_token_hash=token_hash,
        verification_token_expires_at=expires_at,
        token_version=1,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    # 4. Dispatch verification email in background
    email_service = get_email_service()
    await email_service.send_verification_email(
        to_email=user.email,
        full_name=user.full_name,
        raw_token=raw_token,
    )

    # 5. Issue JWT token
    access_token = create_access_token(subject=user.id, email=user.email)

    return AuthResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_verified=user.is_verified,
        access_token=access_token,
        token_type="bearer",
        user=UserProfileResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_verified=user.is_verified,
            created_at=user.created_at,
        ),
    )


@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    response_model=AuthResponse,
    responses={
        status.HTTP_200_OK: {
            "model": AuthResponse,
            "description": "Login successful",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Invalid credentials",
        },
    },
    summary="Login with existing credentials",
)
async def login(
    payload: UserLoginRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AuthResponse:
    """Authenticate with email and password."""
    stmt = select(User).where(User.email == payload.email.lower().strip())
    res = await session.exec(stmt)
    user = res.first()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong email or password",
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email address not verified. Please verify your email before logging in. Check your inbox or use /auth/resend-verification to request a new link.",
        )

    access_token = create_access_token(subject=user.id, email=user.email)

    return AuthResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserProfileResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_verified=user.is_verified,
            created_at=user.created_at,
        ),
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_verified=user.is_verified,
    )


@router.get(
    "/me",
    status_code=status.HTTP_200_OK,
    response_model=UserProfileResponse,
    summary="Get current user profile",
)
async def get_me(
    user: Annotated[User, Depends(get_current_tenant)],
) -> UserProfileResponse:
    """Retrieve profile of authenticated user."""
    return UserProfileResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_verified=user.is_verified,
        created_at=user.created_at,
    )


@router.post(
    "/refresh",
    status_code=status.HTTP_200_OK,
    response_model=dict[str, str],
    summary="Refresh JWT access token",
)
async def refresh_token(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    session: Annotated[AsyncSession, Depends(get_session)] = None,  # type: ignore[assignment]
) -> dict[str, str]:
    """Issue a new JWT token from an existing token."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization token required",
        )
    parts = authorization.strip().split(" ", 1)
    raw_token = parts[1].strip() if len(parts) == 2 and parts[0].lower() == "bearer" else authorization.strip()

    try:
        payload = decode_access_token(raw_token)
        new_token = create_access_token(subject=payload["sub"], email=payload["email"])
        return {"access_token": new_token, "token_type": "bearer"}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired or invalid",
        ) from None


@router.post(
    "/verify-email",
    status_code=status.HTTP_200_OK,
    response_model=VerifyEmailResponse,
    responses={
        status.HTTP_200_OK: {
            "model": VerifyEmailResponse,
            "description": "Email verified successfully",
        },
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorResponse,
            "description": "Invalid or expired token",
        },
    },
    summary="Verify email address with cryptographic token",
)
async def verify_email(
    payload: VerifyEmailRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> VerifyEmailResponse:
    """Validate verification token and activate user email."""
    token_hash = hash_token(payload.token)
    stmt = select(User).where(User.verification_token_hash == token_hash)
    res = await session.exec(stmt)
    user = res.first()

    now = datetime.now(UTC)
    if (
        not user
        or not user.verification_token_expires_at
        or user.verification_token_expires_at < now
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    user.is_verified = True
    user.email_verified_at = now
    user.verification_token_hash = None
    user.verification_token_expires_at = None
    session.add(user)
    await session.commit()

    return VerifyEmailResponse(
        message="Email verified successfully",
        email=user.email,
    )


@router.post(
    "/resend-verification",
    status_code=status.HTTP_200_OK,
    response_model=dict[str, str],
    summary="Resend verification email link",
)
async def resend_verification(
    payload: ResendVerificationRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, str]:
    """Dispatch a fresh verification link if account is unverified."""
    stmt = select(User).where(User.email == payload.email.lower().strip())
    res = await session.exec(stmt)
    user = res.first()

    if user and not user.is_verified:
        raw_token = secrets.token_urlsafe(32)
        user.verification_token_hash = hash_token(raw_token)
        user.verification_token_expires_at = datetime.now(UTC) + timedelta(hours=24)
        session.add(user)
        await session.commit()

        email_service = get_email_service()
        await email_service.send_verification_email(
            to_email=user.email,
            full_name=user.full_name,
            raw_token=raw_token,
        )

    return {
        "message": "If this account is unverified, a new verification email has been sent."
    }


@router.post(
    "/forgot-password",
    status_code=status.HTTP_200_OK,
    response_model=ForgotPasswordResponse,
    summary="Request password recovery link",
)
async def forgot_password(
    payload: ForgotPasswordRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ForgotPasswordResponse:
    """Issue password reset token with anti-enumeration protection."""
    stmt = select(User).where(User.email == payload.email.lower().strip())
    res = await session.exec(stmt)
    user = res.first()

    if user:
        raw_token = secrets.token_urlsafe(32)
        user.reset_token_hash = hash_token(raw_token)
        user.reset_token_expires_at = datetime.now(UTC) + timedelta(minutes=15)
        session.add(user)
        await session.commit()

        email_service = get_email_service()
        await email_service.send_password_reset_email(
            to_email=user.email,
            full_name=user.full_name,
            raw_token=raw_token,
        )

    return ForgotPasswordResponse(
        message="If an account with that email exists, password reset instructions have been sent."
    )


@router.post(
    "/reset-password",
    status_code=status.HTTP_200_OK,
    response_model=ResetPasswordResponse,
    responses={
        status.HTTP_200_OK: {
            "model": ResetPasswordResponse,
            "description": "Password reset successful",
        },
        status.HTTP_400_BAD_REQUEST: {
            "model": ErrorResponse,
            "description": "Invalid or expired token",
        },
    },
    summary="Reset password using recovery token",
)
async def reset_password(
    payload: ResetPasswordRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ResetPasswordResponse:
    """Validate recovery token and update account password."""
    token_hash = hash_token(payload.token)
    stmt = select(User).where(User.reset_token_hash == token_hash)
    res = await session.exec(stmt)
    user = res.first()

    now = datetime.now(UTC)
    if (
        not user
        or not user.reset_token_expires_at
        or user.reset_token_expires_at < now
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, used, or expired reset token",
        )

    user.hashed_password = hash_password(payload.new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    user.token_version += 1
    session.add(user)
    await session.commit()

    email_service = get_email_service()
    await email_service.send_password_changed_notification(
        to_email=user.email,
        full_name=user.full_name,
    )

    return ResetPasswordResponse(
        message="Password has been reset successfully. Please log in with your new password."
    )


@router.post(
    "/change-password",
    status_code=status.HTTP_200_OK,
    response_model=ChangePasswordResponse,
    responses={
        status.HTTP_200_OK: {
            "model": ChangePasswordResponse,
            "description": "Password updated successfully",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Current password incorrect",
        },
    },
    summary="Change password for authenticated user",
)
async def change_password(
    payload: ChangePasswordRequest,
    user: Annotated[User, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> ChangePasswordResponse:
    """Update password with current password verification."""
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    user.hashed_password = hash_password(payload.new_password)
    user.token_version += 1
    session.add(user)
    await session.commit()

    email_service = get_email_service()
    await email_service.send_password_changed_notification(
        to_email=user.email,
        full_name=user.full_name,
    )

    return ChangePasswordResponse(message="Password updated successfully")
