from rest_framework import serializers
from apikeys.models import APIKey


class APIKeyCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)
    scopes = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=True,
    )


class APIKeyListSerializer(serializers.ModelSerializer):
    class Meta:
        model = APIKey
        fields = (
            "id",
            "name",
            "scopes",
            "is_revoked",
            "created_at",
            "revoked_at",
        )
