"""FastAPI dependencies for LogMorph API."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from logmorph.core.exceptions import InvalidApiKeyException
from logmorph.core.keys import hash_api_key, is_valid_api_key_format
from logmorph.db.models import ApiKey
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
