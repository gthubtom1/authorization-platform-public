from __future__ import annotations

from django.urls import path

from . import views
from . import api_views


app_name = "accounts"

urlpatterns = [
    path("api/v1/session/", api_views.api_session, name="api_session"),
    path("api/v1/auth/login/", api_views.api_login, name="api_login"),
    path("api/v1/auth/logout/", api_views.api_logout, name="api_logout"),
    path("api/v1/auth/password/change/", api_views.api_password_change, name="api_password_change"),
    path("api/v1/auth/register/", api_views.api_register, name="api_register"),
    path("api/v1/manage/downstreams/", api_views.api_downstream_collection, name="api_downstream_collection"),
    path("api/v1/manage/downstreams/<uuid:public_id>/status/", api_views.api_downstream_status, name="api_downstream_status"),
    path("api/v1/manage/downstreams/<uuid:public_id>/archive/", api_views.api_downstream_archive, name="api_downstream_archive"),
    path(
        "api/v1/manage/downstreams/<uuid:public_id>/password/reset/",
        api_views.api_downstream_password_reset,
        name="api_downstream_password_reset",
    ),
    path("api/v1/manage/downstreams/<uuid:public_id>/delete/", api_views.api_downstream_delete, name="api_downstream_delete"),
    path("api/v1/manage/invitations/", api_views.api_invitation_collection, name="api_invitation_collection"),
    path("api/v1/manage/invitations/search/", api_views.api_invitation_search, name="api_invitation_search"),
    path("api/v1/manage/invitations/archive/", api_views.api_invitation_archive, name="api_invitation_archive"),
    path("api/v1/manage/invitations/delete/", api_views.api_invitation_delete, name="api_invitation_delete"),
    path("api/v1/manage/invitations/export/", api_views.api_invitation_export, name="api_invitation_export"),
    path(
        "api/v1/manage/invitations/<uuid:public_id>/reveal/",
        api_views.api_invitation_reveal,
        name="api_invitation_reveal",
    ),
    path(
        "api/v1/manage/invitations/<uuid:public_id>/revoke/",
        api_views.api_invitation_revoke,
        name="api_invitation_revoke",
    ),
    path("auth/login/", views.login_view, name="login"),
    path("manage/login/", views.manage_login_view, name="manage_login"),
    path("downstream/login/", views.downstream_login_view, name="downstream_login"),
    path("auth/logout/", views.logout_view, name="logout"),
    path("auth/register/", views.legacy_register_redirect, name="register"),
    path("downstream/register/", views.register_view, name="downstream_register"),
    path("manage/", views.manage_dashboard, name="manage_dashboard"),
    path("manage/invitations/", views.invitation_view, name="invitations"),
    path("manage/invitations/<uuid:public_id>/reveal/", views.reveal_invitation_view, name="invitation_reveal"),
    path("manage/invitations/<uuid:public_id>/revoke/", views.revoke_invitation_view, name="invitation_revoke"),
    path("manage/downstreams/", views.downstream_list, name="downstream_list"),
    path("manage/downstreams/new/", views.create_downstream_view, name="downstream_create"),
    path("manage/downstreams/<uuid:public_id>/", views.downstream_detail, name="downstream_detail"),
    path("manage/downstreams/<uuid:public_id>/archive/", views.archive_downstream_view, name="downstream_archive"),
    path("manage/downstreams/<uuid:public_id>/delete/", views.delete_downstream_view, name="downstream_delete"),
    path("downstream/", views.downstream_dashboard, name="downstream_dashboard"),
    path("downstream/profile/<uuid:public_id>/", views.downstream_profile_detail, name="downstream_profile"),
]
