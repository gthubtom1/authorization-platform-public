from __future__ import annotations

from django.urls import include, path


handler403 = "authorization_platform.core.views.permission_denied"


urlpatterns = [
    path("", include("authorization_platform.accounts.urls")),
    path("", include("authorization_platform.audit.urls")),
    path("", include("authorization_platform.catalog.urls")),
    path("", include("authorization_platform.credits.urls")),
    path("", include("authorization_platform.licensing.urls")),
    path("", include("authorization_platform.releases.urls")),
    path("", include("authorization_platform.analytics.urls")),
    path("", include("authorization_platform.storage_cleanup.urls")),
    path("", include("authorization_platform.backup_control.urls")),
    path("", include("authorization_platform.core.urls")),
]
