from rest_framework import serializers
from security.models import SecurityEvent


class SecurityEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEvent
        fields = [
            "id",
            "event_type",
            "severity",
            "created_at",
            "ip_address",
            "user_agent",
            "metadata",
        ]
        read_only_fields = fields
