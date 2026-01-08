from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.generics import ListCreateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apikeys.models import APIKey
from apikeys.permissions import HasAPIKeyScope
from apikeys.serializers import APIKeyListSerializer, APIKeyCreateSerializer
from apikeys.services.api_key import APIKeyService
from logs.constants import AuditEvent
from logs.services.audit import AuditService
from security.models import SecurityEvent
from security.permissions import IsNotCompromised
from security.services import SecurityEventService


# Create your views here.

class APIKeyListCreateView(ListCreateAPIView):
    permission_classes = [
        IsAuthenticated,
        IsNotCompromised,
        HasAPIKeyScope,
    ]
    required_scope = "keys:read"

    def get_queryset(self):
        return APIKey.objects.filter(
            user=self.request.user,
            is_revoked=False,
        )

    def get_serializer_class(self):
        if self.request.method == "POST":
            return APIKeyCreateSerializer
        return APIKeyListSerializer


class APIKeyRevokeView(APIView):
    permission_classes = [
        IsAuthenticated,
        IsNotCompromised,
        HasAPIKeyScope,
    ]
    required_scope = "keys:write"

    def post(self, request, key_id):
        try:
            api_key = APIKey.objects.get(
                id=key_id,
                user=request.user,
            )
        except APIKey.DoesNotExist:
            raise NotFound("API key not found.")

        APIKeyService.revoke_key(
            api_key=api_key,
            reason="user_revocation",
        )

        return Response(
            {"detail": "API key revoked successfully."},
            status=status.HTTP_200_OK,
        )
