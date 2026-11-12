"""FastAPI dependencies for LogMorph API."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.exceptions import InvalidApiKeyException
from logmorph.core.keys import hash_api_key, is_valid_api_key_format
from logmorph.core.security import decode_access_token
from logmorph.db.models import ApiKey, User
from logmorph.db.session import get_session


async def get_api_key(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    session: Annotated[AsyncSession, Depends(get_session)] = None,  # type: ignore[assignment]
) -> ApiKey:
    """Validate incoming API key from Authorization or X-API-Key header.

    Authenticates the requesting tenant, enforces active status, and updates
    the key's last_used_at audit timestamp.

    Raises:
        InvalidApiKeyException: If the key is missing, improperly formatted,
                                revoked, or not found.
    """
    raw_key: str | None = None

    if authorization:
        parts = authorization.strip().split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            raw_key = parts[1].strip()
        else:
            raw_key = authorization.strip()
    elif x_api_key:
        raw_key = x_api_key.strip()

    if not raw_key:
        raise InvalidApiKeyException(
            detail="API key is required in Authorization or X-API-Key header"
        )

    if not is_valid_api_key_format(raw_key):
        raise InvalidApiKeyException(detail="Invalid or inactive API key")

    key_hash = hash_api_key(raw_key)
    statement = select(ApiKey).where(
        ApiKey.key_hash == key_hash,
        ApiKey.is_active,
    )
    result = await session.exec(statement)
    api_key = result.first()

    if not api_key:
        raise InvalidApiKeyException(detail="Invalid or inactive API key")

    # Update last_used_at timestamp for audit logging
    api_key.last_used_at = datetime.now(UTC)
    session.add(api_key)
    await session.commit()
    await session.refresh(api_key)

    return api_key


async def get_current_user(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    session: Annotated[AsyncSession, Depends(get_session)] = None,  # type: ignore[assignment]
) -> User:
    """Extract authenticated User from JWT Bearer token.

    Raises:
        HTTPException: If token is missing, invalid, expired, or user not found.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = authorization.strip().split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Expected 'Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = parts[1].strip()
    try:
        payload = decode_access_token(raw_token)
        user_id_str = payload.get("sub")
        if not user_id_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing subject claim",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = UUID(user_id_str)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    stmt = select(User).where(User.id == user_id)
    res = await session.exec(stmt)
    user = res.first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account unverified. Please verify your email address to access SaaS resources.",
        )

    return user


async def get_current_tenant(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    session: Annotated[AsyncSession, Depends(get_session)] = None,  # type: ignore[assignment]
) -> User:
    """Authenticate requesting tenant via either JWT Bearer token or API Key.

    Allows dashboard users authenticated via JWT tokens and external services
    authenticated via API keys to access tenant-scoped resources.
    """
    raw_key_or_token: str | None = None

    if authorization:
        parts = authorization.strip().split(" ", 1)
        raw_key_or_token = parts[1].strip() if len(parts) == 2 and parts[0].lower() == "bearer" else authorization.strip()
    elif x_api_key:
        raw_key_or_token = x_api_key.strip()

    if not raw_key_or_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required in Authorization or X-API-Key header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Check if token matches API key pattern
    if is_valid_api_key_format(raw_key_or_token):
        key_hash = hash_api_key(raw_key_or_token)
        key_stmt = select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.is_active)
        key_res = await session.exec(key_stmt)
        api_key = key_res.first()
        if not api_key:
            raise InvalidApiKeyException(detail="Invalid or inactive API key")

        api_key.last_used_at = datetime.now(UTC)
        session.add(api_key)
        await session.commit()

        user_stmt = select(User).where(User.id == api_key.user_id)
        user_res = await session.exec(user_stmt)
        user = user_res.first()
        if not user:
            raise InvalidApiKeyException(detail="Tenant user associated with API key not found")
        if not user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account unverified. Please verify your email address to access SaaS resources.",
            )
        return user

    # 2. Otherwise treat as JWT access token
    try:
        payload = decode_access_token(raw_key_or_token)
        user_id_str = payload.get("sub")
        if not user_id_str:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing subject claim",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = UUID(user_id_str)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    user_stmt = select(User).where(User.id == user_id)
    user_res = await session.exec(user_stmt)
    user = user_res.first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account unverified. Please verify your email address to access SaaS resources.",
        )

    return user
