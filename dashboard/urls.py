from django.urls import path
from dashboard.views import UserDashboardView

app_name = "dashboard"

urlpatterns = [
    path("", UserDashboardView.as_view(), name="overview"),
]
