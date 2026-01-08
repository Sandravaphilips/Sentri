from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated

from security.models import SecurityEvent
from security.serializers import SecurityEventSerializer


class SecurityEventListView(ListAPIView):
    serializer_class = SecurityEventSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return SecurityEvent.objects.filter(
            user=self.request.user
        ).order_by("-created_at")
