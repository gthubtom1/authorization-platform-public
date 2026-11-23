from __future__ import annotations

from django.urls import path

from . import api_views


app_name = "analytics"

urlpatterns = [
    path("api/v1/manage/analytics/summary/", api_views.api_manage_analytics_summary, name="manage_summary"),
    path("api/v1/manage/analytics/summary/export/", api_views.api_manage_analytics_export, name="manage_summary_export"),
    path("api/v1/downstream/analytics/summary/", api_views.api_downstream_analytics_summary, name="downstream_summary"),
]
