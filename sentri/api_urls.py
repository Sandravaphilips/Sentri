from django.urls import path
from apikeys.views import APIKeyListView
from logs.views import AuditLogListView

urlpatterns = [
    path("apikeys/", APIKeyListView.as_view(), name="apikey-list"),
    path("logs/", AuditLogListView.as_view(), name="audit-log-list"),
]
