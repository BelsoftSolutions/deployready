from django.urls import path

from . import views

urlpatterns = [
    path("", views.list_users),
    path("<int:pk>/", views.user_detail),
    path("me/", views.me),
]
