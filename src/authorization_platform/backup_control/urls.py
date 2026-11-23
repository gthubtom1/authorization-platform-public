from django.urls import path

from . import views

app_name = "backup_control"

urlpatterns = [
    path("manage/backup/", views.dashboard, name="dashboard"),
    path("manage/backup/download/<str:name>/", views.download_backup, name="download"),
    path("manage/backup/cleanup/", views.cleanup, name="cleanup"),
    path("api/v1/manage/backup/", views.api_dashboard, name="api_dashboard"),
    path("api/v1/manage/backup/runs/", views.api_backup_run, name="api_backup_run"),
    path("api/v1/manage/backup/destinations/probe/", views.api_backup_destination_probe, name="api_destination_probe"),
    path("api/v1/manage/backup/downloads/<str:name>/", views.api_download_backup, name="api_download"),
    path(
        "api/v1/manage/backup/downloads/<str:name>/delete/",
        views.api_delete_backup_download,
        name="api_delete_download",
    ),
    path("api/v1/manage/backup/restore/inspect/", views.api_restore_inspect, name="api_restore_inspect"),
    path("api/v1/manage/backup/restore/", views.api_restore_apply, name="api_restore_apply"),
]
