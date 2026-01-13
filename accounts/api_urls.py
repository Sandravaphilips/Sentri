from django.urls import path

from .api_views import PublicTokenRefreshView, APILoginView, APISignupView, PublicTokenVerifyView

urlpatterns = [
    path("signup/", APISignupView.as_view(), name="api-signup"),
    path("login/", APILoginView.as_view(), name="api-login"),
    path("refresh/", PublicTokenRefreshView.as_view(), name="api-refresh"),
    path("verify/", PublicTokenVerifyView.as_view(), name="api-verify"),
]
