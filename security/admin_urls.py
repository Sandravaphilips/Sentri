from django.urls import path
from security.admin_views import (
    AdminSecurityOverviewView,
    AdminUserListView,
    AdminUserDetailView,
    admin_unlock_user,
    admin_clear_compromise,
    admin_revoke_api_keys,
)

app_name = "security_admin"

urlpatterns = [
    path("overview/", AdminSecurityOverviewView.as_view(), name="overview"),
    path("users/", AdminUserListView.as_view(), name="user_list"),
    path("users/<int:user_id>/", AdminUserDetailView.as_view(), name="user_detail"),

    path("users/<int:user_id>/unlock/", admin_unlock_user, name="unlock_user"),
    path("users/<int:user_id>/clear-compromise/", admin_clear_compromise, name="clear_compromise"),
    path("users/<int:user_id>/revoke-keys/", admin_revoke_api_keys,  name="revoke_keys"),
]
