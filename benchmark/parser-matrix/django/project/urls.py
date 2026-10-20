from django.contrib import admin
from django.urls import include, path

from users import views as user_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("health/", user_views.health),
    path("api/users/", include("users.urls")),
]
