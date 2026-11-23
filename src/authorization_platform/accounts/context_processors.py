from __future__ import annotations

from .services import is_active_downstream, is_platform_admin


def account_roles(request):
    user = request.user
    return {
        "is_platform_admin_user": is_platform_admin(user),
        "is_active_downstream_user": is_active_downstream(user),
    }
