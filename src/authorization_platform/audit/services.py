from __future__ import annotations

import uuid

from authorization_platform.accounts.roles import role_for_user

from .models import AuditEvent, AuditOutcome


def record_event(*, actor=None, action: str, outcome: str, request_id: str | None = None, ip_address: str | None = None, object_type: str = "", object_public_id: str = "", reason_code: str = "", metadata: dict | None = None) -> AuditEvent:
    if outcome not in {AuditOutcome.SUCCESS, AuditOutcome.FAILURE}:
        raise ValueError("invalid audit outcome")
    if not request_id:
        request_id = f"local-{uuid.uuid4().hex}"
    actor_role = "anonymous" if actor is None else role_for_user(actor)
    return AuditEvent.objects.create(
        actor=actor,
        actor_role=actor_role,
        action=action,
        outcome=outcome,
        object_type=object_type,
        object_public_id=str(object_public_id) if object_public_id else "",
        request_id=request_id,
        ip_address=ip_address,
        reason_code=reason_code,
        metadata=metadata or {},
    )
