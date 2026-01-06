from django.urls import path

from apikeys.api_views import APIKeyListCreateView, APIKeyRevokeView

urlpatterns = [
    path("keys/", APIKeyListCreateView.as_view(), name="api-key-list-create"),
    path(
        "keys/<uuid:key_id>/revoke/",
        APIKeyRevokeView.as_view(),
        name="api-key-revoke",
    ),
]
