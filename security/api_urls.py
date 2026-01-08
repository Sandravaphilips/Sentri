from django.urls import path
from security.api_views import SecurityEventListView

urlpatterns = [
    path("security/events/", SecurityEventListView.as_view(), name="security-events"),
]
