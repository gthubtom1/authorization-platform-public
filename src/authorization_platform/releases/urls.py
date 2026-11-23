from __future__ import annotations

from django.urls import path

from . import api_views
from . import views


app_name = "releases"

urlpatterns = [
    path("manage/releases/", views.manage_releases, name="manage_page"),
    path("api/v1/manage/releases/", api_views.api_manage_releases, name="manage_collection"),
    path("api/v1/manage/releases/external/", api_views.api_publish_external_release, name="publish_external"),
    path("api/v1/manage/releases/<uuid:release_id>/external-url/", api_views.api_update_external_release_url, name="update_external_url"),
    path("api/v1/manage/releases/<uuid:release_id>/publish/", api_views.api_publish_release, name="publish"),
    path("api/v1/manage/releases/<uuid:release_id>/withdraw/", api_views.api_withdraw_release, name="withdraw"),
    path("api/v1/manage/releases/<uuid:release_id>/delete-package/", api_views.api_delete_release_package, name="delete_package"),
    path("api/v1/manage/releases/<uuid:release_id>/discard/", api_views.api_discard_release, name="discard"),
    path("api/v1/manage/releases/<uuid:release_id>/archive/", api_views.api_archive_release, name="archive"),
    path("api/v1/manage/releases/<uuid:release_id>/version/", api_views.api_update_release_version, name="update_version"),
    path("api/v1/public/software/<str:software_id>/profiles/<str:profile_id>/releases/", api_views.api_public_release_registry, name="public_registry"),
    path("api/v1/public/software/<str:software_id>/profiles/<str:profile_id>/releases/<uuid:release_id>/download/", api_views.api_public_release_download, name="public_download"),
]
