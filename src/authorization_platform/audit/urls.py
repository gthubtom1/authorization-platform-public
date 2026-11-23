from __future__ import annotations

from django.urls import path

from . import api_views
from . import views


app_name = "audit"

urlpatterns = [
    path("api/v1/manage/audit/", api_views.api_manage_audit, name="api_manage_audit"),
    path("api/v1/manage/audit/export/", api_views.api_manage_audit_export, name="api_manage_audit_export"),
    path("api/v1/downstream/audit/", api_views.api_downstream_audit, name="api_downstream_audit"),
    path("api/v1/downstream/audit/export/", api_views.api_downstream_audit_export, name="api_downstream_audit_export"),
    path("manage/audit/", views.admin_audit_log, name="admin_log"),
    path("manage/audit/export/", views.admin_audit_export, name="admin_export"),
    path("downstream/audit/", views.downstream_audit_log, name="downstream_log"),
]
