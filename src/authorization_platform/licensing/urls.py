from __future__ import annotations

from django.urls import path

from . import api
from . import api_views
from . import views


app_name = "licensing"

urlpatterns = [
    path("api/v1/downstream/licenses/preview/", api_views.api_downstream_license_preview, name="api_downstream_license_preview"),
    path("api/v1/downstream/licenses/issue/", api_views.api_downstream_license_issue, name="api_downstream_license_issue"),
    path("api/v1/downstream/licenses/cards/", api_views.api_downstream_license_cards, name="api_downstream_license_cards"),
    path("api/v1/downstream/devices/", api_views.api_downstream_devices, name="api_downstream_devices"),
    path(
        "api/v1/downstream/authorizations/<uuid:authorization_id>/devices/<str:device_id>/reset/",
        api_views.api_downstream_device_reset,
        name="api_downstream_device_reset",
    ),
    path("api/v1/downstream/licenses/cards/search/", api_views.api_downstream_license_card_search, name="api_downstream_license_card_search"),
    path("api/v1/downstream/licenses/cards/reclaim-preview/", api_views.api_downstream_license_reclaim_preview, name="api_downstream_license_reclaim_preview"),
    path("api/v1/downstream/licenses/cards/reclaim/", api_views.api_downstream_license_reclaim, name="api_downstream_license_reclaim"),
    path("api/v1/downstream/licenses/cards/<uuid:public_id>/reveal/", api_views.api_downstream_license_reveal, name="api_downstream_license_reveal"),
    path("api/v1/manage/licenses/cards/", api_views.api_manage_license_cards, name="api_manage_license_cards"),
    path("api/v1/manage/licenses/cards/search/", api_views.api_manage_license_card_search, name="api_manage_license_card_search"),
    path("api/v1/manage/licenses/cards/reclaim-preview/", api_views.api_manage_license_reclaim_preview, name="api_manage_license_reclaim_preview"),
    path("api/v1/manage/licenses/cards/reclaim/", api_views.api_manage_license_reclaim, name="api_manage_license_reclaim"),
    path("api/v1/manage/licenses/cards/archive/", api_views.api_manage_license_archive, name="api_manage_license_archive"),
    path("api/v1/manage/licenses/cards/delete/", api_views.api_manage_license_delete, name="api_manage_license_delete"),
    path("api/v1/manage/licenses/cards/<uuid:public_id>/reveal/", api_views.api_manage_license_reveal, name="api_manage_license_reveal"),
    path("api/v1/manage/licenses/cards/export/", api_views.api_manage_license_export, name="api_manage_license_export"),
    path(
        "api/v1/manage/authorization-signing-key/",
        api_views.api_authorization_signing_key,
        name="api_authorization_signing_key",
    ),
    path("api/v1/downstream/licenses/cards/export/", api_views.api_downstream_license_export, name="api_downstream_license_export"),
    path("api/v1/manage/authorizations/", api_views.api_manage_authorizations, name="api_manage_authorizations"),
    path("api/v1/manage/authorizations/export/", api_views.api_manage_authorizations_export, name="api_manage_authorizations_export"),
    path(
        "api/v1/manage/authorizations/renew-preview/",
        api_views.api_manage_authorization_renew_preview,
        name="api_manage_authorization_renew_preview",
    ),
    path(
        "api/v1/manage/authorizations/renew/",
        api_views.api_manage_authorization_renew,
        name="api_manage_authorization_renew",
    ),
    path(
        "api/v1/manage/authorizations/bulk-revoke/",
        api_views.api_manage_authorization_bulk_revoke,
        name="api_manage_authorization_bulk_revoke",
    ),
    path(
        "api/v1/manage/authorizations/bulk-block/",
        api_views.api_manage_authorization_bulk_block,
        name="api_manage_authorization_bulk_block",
    ),
    path(
        "api/v1/manage/authorizations/bulk-unblock/",
        api_views.api_manage_authorization_bulk_unblock,
        name="api_manage_authorization_bulk_unblock",
    ),
    path(
        "api/v1/manage/authorizations/<uuid:authorization_id>/revoke/",
        api_views.api_manage_authorization_revoke,
        name="api_manage_authorization_revoke",
    ),
    path(
        "api/v1/manage/authorizations/<uuid:authorization_id>/devices/<str:device_id>/reset/",
        api_views.api_manage_authorization_device_reset,
        name="api_manage_authorization_device_reset",
    ),
    path(
        "api/v1/manage/authorizations/<uuid:authorization_id>/devices/<str:device_id>/block/",
        api_views.api_manage_authorization_device_block,
        name="api_manage_authorization_device_block",
    ),
    path(
        "api/v1/manage/authorizations/<uuid:authorization_id>/devices/<str:device_id>/unblock/",
        api_views.api_manage_authorization_device_unblock,
        name="api_manage_authorization_device_unblock",
    ),
    path("api/v1/public/licenses/activate", api.activate_api, name="public_license_activate"),
    path("api/v1/public/licenses/verify", api.verify_api, name="public_license_verify"),
    path("api/v1/public/licenses/deactivate", api.deactivate_api, name="public_license_deactivate"),
    path("api/v1/public/licenses/launch-ticket", api.launch_ticket_api, name="public_license_launch_ticket"),
    path("api/v1/public/licenses/launch-ticket/consume", api.launch_ticket_consume_api, name="public_license_launch_ticket_consume"),
    path("manage/authorizations/", views.authorization_admin_dashboard, name="authorization_admin"),
    path("manage/authorizations/<uuid:authorization_id>/configuration/", views.admin_authorization_configuration, name="admin_authorization_configuration"),
    path("manage/authorizations/<uuid:authorization_id>/revoke/", views.admin_revoke_authorization, name="admin_revoke_authorization"),
    path("manage/authorizations/devices/<uuid:device_id>/block/", views.admin_block_device, name="admin_block_device"),
    path("manage/authorizations/devices/<uuid:device_id>/unblock/", views.admin_unblock_device, name="admin_unblock_device"),
    path("downstream/licenses/", views.batch_list, name="batch_list"),
    path("downstream/licenses/batches/<uuid:batch_id>/export/", views.batch_export, name="batch_export"),
    path("downstream/licenses/cards/<uuid:public_id>/reveal/", views.card_reveal, name="card_reveal"),
    path("downstream/licenses/cards/<uuid:public_id>/reclaim/", views.card_reclaim, name="card_reclaim"),
]
