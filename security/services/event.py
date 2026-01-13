from django.utils import timezone

from security.models import SecurityEvent


class SecurityEventService:
    @staticmethod
    def emit(
        *,
        event_type,
        severity=SecurityEvent.Severity.LOW,
        user=None,
        api_key=None,
        request=None,
        ip_address=None,
        user_agent=None,
        metadata=None,
    ):
        if metadata is None:
            metadata = {}

        if request:
            ip_address = ip_address or SecurityEventService._get_ip(request)
            user_agent = user_agent or request.META.get("HTTP_USER_AGENT", "")

        event = SecurityEvent.objects.create(
            event_type=event_type,
            severity=severity,
            user=user,
            api_key=api_key,
            ip_address=ip_address,
            user_agent=user_agent or "",
            metadata=metadata,
            created_at=timezone.now(),
        )

        return event

    @staticmethod
    def _get_ip(request):
        """
        Implementation to avoid dependency hub
        """
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()

        return request.META.get("REMOTE_ADDR")
