"""Security telemetry and audit logging for LogMorph."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

security_logger = logging.getLogger("logmorph.security")


def log_idor_probe(
    resource_type: str,
    resource_id: str,
    requesting_tenant_id: str | UUID,
    actual_owner_tenant_id: str | UUID,
    action: str = "READ",
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit structured security warning log when a cross-tenant resource probe is detected.

    Args:
        resource_type: Type of resource (e.g. 'LogRecord', 'LogSource', 'ApiKey').
        resource_id: Identifier of the probed resource.
        requesting_tenant_id: Tenant UUID attempting unauthorized access.
        actual_owner_tenant_id: Genuine owning tenant UUID.
        action: Attempted operation ('READ', 'DELETE', etc.).
        extra: Additional contextual metadata if available.
    """
    payload: dict[str, Any] = {
        "event_type": "IDOR_PROBE",
        "resource_type": resource_type,
        "resource_id": str(resource_id),
        "action": action,
        "requesting_tenant_id": str(requesting_tenant_id),
        "actual_owner_tenant_id": str(actual_owner_tenant_id),
    }
    if extra:
        payload.update(extra)

    security_logger.warning(
        "SECURITY: Cross-tenant resource probe detected [resource=%s, id=%s, requesting_tenant=%s, owner=%s]",
        resource_type,
        resource_id,
        requesting_tenant_id,
        actual_owner_tenant_id,
        extra=payload,
    )
