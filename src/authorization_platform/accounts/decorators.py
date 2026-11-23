from __future__ import annotations

import hashlib
from functools import wraps

from django.contrib.auth import logout
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from authorization_platform.audit.models import AuditOutcome
from authorization_platform.audit.services import record_event

from .services import get_downstream_profile, is_active_downstream, is_platform_admin


def _admin_access_request_id(request) -> str:
    supplied = request.headers.get("X-Request-Id", "").strip()
    if not supplied:
        supplied = request.path
    digest = hashlib.sha256(supplied.encode("utf-8")).hexdigest()
    return f"admin-{digest}"


def platform_admin_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path(), login_url=reverse("accounts:manage_login"))
        if not is_platform_admin(request.user):
            try:
                record_event(
                    actor=request.user,
                    action="admin.access",
                    outcome=AuditOutcome.FAILURE,
                    request_id=_admin_access_request_id(request),
                    ip_address=request.META.get("REMOTE_ADDR") or None,
                    reason_code="FORBIDDEN",
                    metadata={"path": request.path[:128]},
                )
            except Exception:
                pass
            raise PermissionDenied
        return view(request, *args, **kwargs)

    return wrapped


def active_downstream_required(view):
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path(), login_url=reverse("accounts:downstream_login"))
        if is_platform_admin(request.user):
            raise PermissionDenied
        profile = get_downstream_profile(request.user)
        expected_version = request.session.get("downstream_session_version")
        if not is_active_downstream(request.user) or not profile or str(expected_version) != str(profile.session_version):
            logout(request)
            return redirect_to_login("/downstream/", login_url=reverse("accounts:downstream_login"))
        return view(request, *args, **kwargs)

    return wrapped
