from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apikeys.models import APIKey
from apikeys.serializers import APIKeyListSerializer, APIKeyCreateSerializer
from apikeys.services.api_key import APIKeyService
from logs.constants import AuditEvent
from logs.services.audit import AuditService


# Create your views here.

class APIKeyListCreateView(APIView):
    def get(self, request):
        keys = APIKey.objects.filter(user=request.user)
        serializer = APIKeyListSerializer(keys, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = APIKeyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        api_key, raw_key = APIKeyService.create_key(
            user=request.user,
            name=serializer.validated_data["name"],
            scopes=serializer.validated_data["scopes"],
        )

        AuditService.log_audit_event(
            request=request,
            user=request.user,
            action=AuditEvent.API_KEY_CREATED,
            status_code=status.HTTP_201_CREATED,
            metadata={"api_key_id": str(api_key.id)},
        )

        return Response(
            {
                "id": api_key.id,
                "name": api_key.name,
                "scopes": api_key.scopes,
                "api_key": raw_key,
            },
            status=status.HTTP_201_CREATED,
        )


class APIKeyRevokeView(APIView):
    def post(self, request, key_id):
        api_key = get_object_or_404(
            APIKey,
            id=key_id,
            user=request.user,
            is_revoked=False,
        )

        api_key.is_revoked = True
        api_key.revoked_at = timezone.now()
        api_key.save(update_fields=["is_revoked", "revoked_at"])

        AuditService.log_audit_event(
            request=request,
            user=request.user,
            action=AuditEvent.API_KEY_REVOKED,
            status_code=status.HTTP_200_OK,
            metadata={"api_key_id": str(api_key.id)},
        )

        return Response(
            {"detail": "API key revoked."},
            status=status.HTTP_200_OK,
        )
