from __future__ import annotations

from django.urls import path

from . import api_views
from . import views


app_name = "credits"

urlpatterns = [
    path("api/v1/public/quota-settings/", api_views.api_public_quota_settings, name="api_public_quota_settings"),
    path("api/v1/manage/credits/", api_views.api_manage_credits, name="api_manage_credits"),
    path("api/v1/manage/credits/settings/", api_views.api_update_quota_settings, name="api_update_quota_settings"),
    path("api/v1/manage/credits/adjust/", api_views.api_adjust_credits, name="api_adjust_credits"),
    path(
        "api/v1/manage/credits/recover-deleted/",
        api_views.api_recover_deleted_credits,
        name="api_recover_deleted_credits",
    ),
    path("api/v1/manage/credits/cards/", api_views.api_issue_quota_cards, name="api_issue_quota_cards"),
    path(
        "api/v1/manage/credits/cards/<uuid:public_id>/revoke/",
        api_views.api_revoke_quota_card,
        name="api_revoke_quota_card",
    ),
    path(
        "api/v1/manage/credits/cards/<uuid:public_id>/reveal/",
        api_views.api_reveal_quota_card,
        name="api_reveal_quota_card",
    ),
    path("api/v1/manage/credits/cards/search/", api_views.api_search_quota_card, name="api_search_quota_card"),
    path(
        "api/v1/manage/credits/cards/archive/",
        api_views.api_manage_quota_card_archive,
        name="api_manage_quota_card_archive",
    ),
    path(
        "api/v1/manage/credits/cards/delete/",
        api_views.api_manage_quota_card_delete,
        name="api_manage_quota_card_delete",
    ),
    path(
        "api/v1/manage/credits/cards/export/",
        api_views.api_manage_quota_card_export,
        name="api_manage_quota_card_export",
    ),
    path(
        "api/v1/manage/credits/ledger/export/",
        api_views.api_manage_credit_ledger_export,
        name="api_manage_credit_ledger_export",
    ),
    path("api/v1/downstream/credits/", api_views.api_downstream_credits, name="api_downstream_credits"),
    path("manage/credits/", views.admin_dashboard, name="admin_dashboard"),
    path("manage/credits/cards/<uuid:public_id>/reveal/", views.card_reveal, name="card_reveal"),
    path("downstream/credits/", views.downstream_ledger, name="downstream_ledger"),
]
