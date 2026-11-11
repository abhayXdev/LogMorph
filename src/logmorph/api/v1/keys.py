"""API Key Management endpoints for tenant ingestion authentication."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.api.deps import get_current_tenant
from logmorph.core.keys import generate_api_key
from logmorph.db.models import ApiKey, User
from logmorph.db.session import get_session
from logmorph.schemas.auth import ApiKeyCreateRequest
from logmorph.schemas.errors import ErrorResponse

router = APIRouter(prefix="/keys", tags=["API Key Management"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=dict[str, Any],
    responses={
        status.HTTP_201_CREATED: {
            "description": "API key generated successfully",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": ErrorResponse,
            "description": "Authentication required",
        },
    },
    summary="Generate a new API key",
    description="Generate a new ingestion API key. The raw secret is returned only once.",
)
async def create_key(
    payload: ApiKeyCreateRequest,
    user: Annotated[User, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Provision a new API key for the tenant."""
    key_data = generate_api_key()

    api_key = ApiKey(
        name=payload.name.strip(),
        key_hash=key_data.key_hash,
        key_prefix=key_data.key_prefix,
        is_active=True,
        user_id=user.id,
    )
    session.add(api_key)
    await session.commit()
    await session.refresh(api_key)

    return {
        "id": api_key.id,
        "name": api_key.name,
        "key": key_data.raw_key,
        "key_prefix": api_key.key_prefix,
        "created_at": api_key.created_at,
        "is_active": api_key.is_active,
    }


@router.get(
    "",
    status_code=status.HTTP_200_OK,
    response_model=dict[str, Any],
    summary="List all API keys",
    description="List active API keys with masked prefixes for the current tenant.",
)
async def list_keys(
    user: Annotated[User, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """List all API keys belonging to the authenticated tenant."""
    stmt = (
        select(ApiKey)
        .where(ApiKey.user_id == user.id)
        .order_by(ApiKey.created_at.desc())  # type: ignore[attr-defined]
    )
    res = await session.exec(stmt)
    keys = res.all()

    return {
        "keys": [
            {
                "id": k.id,
                "name": k.name,
                "key_prefix": f"{k.key_prefix}****",
                "created_at": k.created_at,
                "last_used_at": k.last_used_at,
                "is_active": k.is_active,
            }
            for k in keys
        ],
        "total": len(keys),
    }


@router.delete(
    "/{key_id}",
    status_code=status.HTTP_200_OK,
    response_model=dict[str, str],
    responses={
        status.HTTP_200_OK: {
            "description": "API key revoked successfully",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "Key not found",
        },
    },
    summary="Revoke an API key",
)
async def revoke_key(
    key_id: str,
    user: Annotated[User, Depends(get_current_tenant)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, str]:
    """Revoke and delete an API key."""
    stmt = select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user.id)
    res = await session.exec(stmt)
    key = res.first()

    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    await session.delete(key)
    await session.commit()

    return {
        "message": "API key revoked successfully",
        "key_id": key_id,
    }
