from django.urls import path
from . views import *
from . import views

urlpatterns = [
    path('index', views.index, name='index'),
    path('upload/', index, name='upload'),
    path('login/', views.superuser_login, name='superuser_login'),
    path('superuser-logout/', views.superuser_logout, name='superuser_logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('category/', category, name='category'),
    path("state", views.state_district, name="state_district"),
    path('inbox', inbox, name='inbox'),
    path('unread-count/', views.unread_uploads_count, name='unread_uploads_count'),
    path("upload/open/<int:pk>/", views.open_upload, name="open_upload"),
    path("upload/delete/<int:pk>/", views.delete_upload, name="delete_upload"),
    path('data',data,name='data'),
    path("get-subcategories/<str:category_id>/", views.get_subcategories, name="get_subcategories"),
    path("get-districts/<str:state_id>/", views.get_districts, name="get_districts"),
    path('usercreate', usercreate, name='usercreate'),
    path("superuser/change-password/",views.superuser_change_password,name="superuser_change_password"),


    path("list/", views.data_list, name="data_list"),
    path("data/export/", views.data_export, name="data_export"),
    path('userlist',views.userlist, name='userlist'),


    path('',views.userlogin, name='userlogin'),
    path('logout/', userlogout, name='userlogout'),



]