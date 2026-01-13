from django.urls import path, include
from django.contrib.auth import views as auth_views

from accounts.views import SignUpView

urlpatterns = [
    path("accounts/", include("django.contrib.auth.urls")),
    path("accounts/signup/", SignUpView.as_view(), name="signup"),
]
