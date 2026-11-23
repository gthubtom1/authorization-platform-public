from django.urls import path
from . import views

urlpatterns = [
    path('', views.catalog, name='catalog'),
    path('health/', views.health, name='health'),
    path('image/<int:pk>/', views.image, name='image'),
    path('go/<int:pk>/<str:action>/', views.outbound, name='outbound'),
    path('manage/login/', views.sign_in, name='login'),
    path('manage/logout/', views.sign_out, name='logout'),
    path('manage/password/', views.password, name='password'),
    path('manage/', views.products, name='products'),
    path('manage/products/new/', views.product_edit, name='product_new'),
    path('manage/products/<int:pk>/', views.product_edit, name='product_edit'),
    path('manage/products/<int:pk>/preview/', views.product_preview, name='product_preview'),
    path('manage/products/<int:pk>/action/', views.product_action, name='product_action'),
    path('manage/categories/', views.categories, name='categories'),
    path('manage/categories/new/', views.category_edit, name='category_new'),
    path('manage/categories/<int:pk>/', views.category_edit, name='category_edit'),
    path('manage/categories/<int:pk>/delete/', views.category_delete, name='category_delete'),
    path('manage/settings/', views.site_edit, name='site_settings'),
]
