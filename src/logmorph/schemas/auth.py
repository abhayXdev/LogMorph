"""Authentication, profile, password lifecycle, and API key management schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

# ==============================================================================
# 1. User Authentication & Profile
# ==============================================================================


class UserSignupRequest(BaseModel):
    """User registration payload."""

    model_config = ConfigDict(frozen=True)

    email: EmailStr
    password: str = Field(min_length=8, description="Minimum 8 characters password.")
    full_name: str = Field(min_length=1, max_length=100)


class UserLoginRequest(BaseModel):
    """User login credential payload."""

    model_config = ConfigDict(frozen=True)

    email: EmailStr
    password: str = Field(min_length=1)


class UserProfileResponse(BaseModel):
    """User profile response model."""

    model_config = ConfigDict(from_attributes=True)

    id: str | UUID
    email: str
    full_name: str
    is_verified: bool = False
    created_at: datetime | None = None


class AuthResponse(BaseModel):
    """Successful authentication response containing JWT access token."""

    model_config = ConfigDict(frozen=True)

    access_token: str
    token_type: str = "bearer"
    user: UserProfileResponse | None = None
    id: str | UUID | None = None
    email: str | None = None
    full_name: str | None = None
    is_verified: bool = False


# ==============================================================================
# 2. Email Verification & Password Recovery
# ==============================================================================


class VerifyEmailRequest(BaseModel):
    """Email verification token submission."""

    model_config = ConfigDict(frozen=True)

    token: str = Field(min_length=16, description="Cryptographic verification token.")


class VerifyEmailResponse(BaseModel):
    """Acknowledgement of successful email verification."""

    model_config = ConfigDict(frozen=True)

    message: str = "Email verified successfully"
    email: str


class ResendVerificationRequest(BaseModel):
    """Request to re-dispatch email verification link."""

    model_config = ConfigDict(frozen=True)

    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    """Password recovery request."""

    model_config = ConfigDict(frozen=True)

    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    """Anti-enumeration acknowledgement of password reset request."""

    model_config = ConfigDict(frozen=True)

    message: str = (
        "If an account with that email exists, password reset instructions have been sent."
    )


class ResetPasswordRequest(BaseModel):
    """Password reset submission with recovery token."""

    model_config = ConfigDict(frozen=True)

    token: str = Field(min_length=16, description="Recovery token.")
    new_password: str = Field(min_length=8, description="New secure password.")


class ResetPasswordResponse(BaseModel):
    """Acknowledgement of password reset."""

    model_config = ConfigDict(frozen=True)

    message: str = (
        "Password has been reset successfully. Please log in with your new password."
    )


class ChangePasswordRequest(BaseModel):
    """In-app password change for authenticated users."""

    model_config = ConfigDict(frozen=True)

    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8)


class ChangePasswordResponse(BaseModel):
    """Acknowledgement of password change."""

    model_config = ConfigDict(frozen=True)

    message: str = "Password updated successfully"


# ==============================================================================
# 3. API Key Management
# ==============================================================================


class ApiKeyCreateRequest(BaseModel):
    """Payload to provision a new ingestion API key."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(
        min_length=1, max_length=100, description="Display name for the API key."
    )


class ApiKeyResponse(BaseModel):
    """Public representation of an API key (safe, secret masked)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    key_prefix: str
    is_active: bool
    created_at: datetime
    last_used_at: datetime | None = None


class ApiKeyCreatedResponse(ApiKeyResponse):
    """Returned once upon key creation, containing the raw secret key."""

    raw_key: str
