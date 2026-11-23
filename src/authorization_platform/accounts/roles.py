from __future__ import annotations


ADMIN_GROUP = "platform_admin"
DOWNSTREAM_GROUP = "downstream"


def is_platform_admin_user(user) -> bool:
    return bool(
        user
        and user.is_authenticated
        and user.is_active
        and (user.is_superuser or user.groups.filter(name=ADMIN_GROUP).exists())
    )


def role_for_user(user) -> str:
    if is_platform_admin_user(user):
        return "platform_admin"
    if user and user.is_authenticated and user.is_active and user.groups.filter(name=DOWNSTREAM_GROUP).exists():
        return "downstream"
    return "unknown"
