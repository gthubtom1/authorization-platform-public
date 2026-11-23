from __future__ import annotations

from django.urls import path

from . import views
from . import api_views


app_name = "catalog"

urlpatterns = [
    path("api/v1/manage/catalog/", api_views.api_catalog_collection, name="api_catalog_collection"),
    path(
        "api/v1/manage/catalog/software/<str:software_id>/integration-config/",
        api_views.api_software_integration_config,
        name="api_software_integration_config",
    ),
    path(
        "api/v1/manage/catalog/software/<str:software_id>/status/",
        api_views.api_catalog_software_status,
        name="api_catalog_software_status",
    ),
    path(
        "api/v1/manage/catalog/software/<str:software_id>/profiles/<str:profile_id>/policy/revise/",
        api_views.api_catalog_policy_revise,
        name="api_catalog_policy_revise",
    ),
    path("api/v1/manage/catalog/plans/", api_views.api_catalog_plan_create, name="api_catalog_plan_create"),
    path("api/v1/manage/catalog/plans/<str:plan_id>/revise/", api_views.api_catalog_plan_revise, name="api_catalog_plan_revise"),
    path("api/v1/manage/catalog/plans/<str:plan_id>/status/", api_views.api_catalog_plan_status, name="api_catalog_plan_status"),
    path("api/v1/manage/catalog/plans/<str:plan_id>/delete/", api_views.api_catalog_plan_delete, name="api_catalog_plan_delete"),
    path("api/v1/manage/catalog/access/<str:downstream_public_id>/", api_views.api_catalog_access, name="api_catalog_access"),
    path("api/v1/manage/catalog/export/", api_views.api_manage_catalog_export, name="api_manage_catalog_export"),
    path(
        "api/v1/manage/software/<str:software_id>/profiles/<str:profile_id>/configuration/",
        api_views.api_manage_profile_configuration,
        name="api_manage_profile_configuration",
    ),
    path("api/v1/downstream/catalog/", api_views.api_downstream_catalog, name="api_downstream_catalog"),
    path("api/v1/downstream/support/<str:software_id>/", api_views.api_downstream_support, name="api_downstream_support"),
    path("manage/software/", views.software_list, name="software_list"),
    path("manage/software/new/", views.software_create, name="software_create"),
    path("manage/software/<slug:software_id>/", views.software_detail, name="software_detail"),
    path("manage/software/<slug:software_id>/status/", views.software_status_update, name="software_status_update"),
    path("manage/software/<slug:software_id>/profiles/new/", views.profile_create, name="profile_create"),
    path("manage/software/<slug:software_id>/profiles/<slug:profile_id>/policies/new/", views.policy_create, name="policy_create"),
    path("manage/software/<slug:software_id>/profiles/<slug:profile_id>/capabilities/new/", views.capability_create, name="capability_create"),
    path("manage/software/<slug:software_id>/profiles/<slug:profile_id>/configuration/", views.profile_configuration, name="profile_configuration"),
    path("manage/software/<slug:software_id>/plans/new/", views.plan_create, name="plan_create"),
    path("manage/software/<slug:software_id>/access/", views.software_access, name="software_access"),
    path("manage/software/<slug:software_id>/access/<uuid:downstream_public_id>/configuration/", views.admin_downstream_configuration, name="admin_downstream_configuration"),
    path("downstream/software/", views.downstream_software, name="downstream_software"),
    path("downstream/software/<slug:software_id>/configuration/", views.downstream_configuration, name="downstream_configuration"),
]
