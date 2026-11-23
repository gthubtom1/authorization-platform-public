from django.urls import path
from files import views

urlpatterns = [
    path('', views.root),
    path('healthz/', views.health),
    path('manage/', views.index, name='index'),
    path('manage/login/', views.sign_in, name='login'),
    path('manage/logout/', views.sign_out, name='logout'),
    path('manage/settings/', views.site_settings, name='settings'),
    path('manage/api/uploads/', views.upload_start),
    path('manage/api/uploads/<uuid:upload_id>/', views.upload_detail),
    path('manage/api/uploads/<uuid:upload_id>/chunk/', views.upload_chunk),
    path('manage/api/uploads/<uuid:upload_id>/finish/', views.upload_finish),
    path('manage/api/actions/', views.actions),
    path('manage/api/files/<uuid:item_id>/', views.details),
    path('d/<uuid:item_id>/', views.fixed_download, name='fixed'),
    path('f/<uuid:blob_id>/', views.file_download, name='file'),
]
handler404 = 'files.views.not_found'
handler500 = 'files.views.server_error'
