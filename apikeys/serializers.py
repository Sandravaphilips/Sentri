from rest_framework import serializers
from apikeys.models import APIKey
from apikeys.services import APIKeyService


class APIKeyCreateSerializer(serializers.ModelSerializer):
    key = serializers.CharField(read_only=True)
    key_note = serializers.CharField(read_only=True)

    class Meta:
        model = APIKey
        fields = [
            "id",
            "name",
            "scopes",
            "expires_at",
            "key",
            "key_note",
        ]
        read_only_fields = ["id", "key", "key_note"]

    def create(self, validated_data):
        api_key, raw_key = APIKeyService.create_key(
            user=self.context["request"].user,
            name=validated_data["name"],
            scopes=validated_data["scopes"],
            expires_at=validated_data.get("expires_at"),
        )

        api_key.key = raw_key
        api_key.key_note = "Copy this key now. It will not be shown again."
        return api_key


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
