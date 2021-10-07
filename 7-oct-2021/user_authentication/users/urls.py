from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path
from django.views.generic.base import TemplateView
from users import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", views.home, name="home"),
    path("register/", views.register, name="register"),
    path(
        "login/", auth_views.LoginView.as_view(template_name="login.html"), name="login"
    ),
    path("authentication/", views.authentication, name="aunthecated"),
    path("logout/", views.logout_user, name="logout"),
    path(
        "password_reset_request/",
        views.password_reset_request,
        name="request_forgot_password",
    ),
    path(
        "password_reset/done/",
        TemplateView.as_view(template_name="password_reset_done.html"),
        name="password_reset_done",
    ),
    path(
        "reset/<uidb64>/<token>/",
        TemplateView.as_view(template_name="password_reset_confirm.html"),
        name="password_reset_confirm",
    ),
    path("password_confirm/", views.password_confirm, name="password_confirm"),
]
