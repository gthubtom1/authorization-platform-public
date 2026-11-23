from __future__ import annotations

from django.urls import path

from . import api_views


app_name = "storage_cleanup"

urlpatterns = [
    path("api/v1/manage/storage/cleanup/", api_views.api_manage_storage_cleanup, name="manage_cleanup"),
]
