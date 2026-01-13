from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied

from security.models import SecurityEvent
from security.services import SecurityEventService, CompromiseDetectionService


class SentriAuthBackend(ModelBackend):
    def user_can_authenticate(self, user):
        if hasattr(user, "is_account_locked") and user.is_account_locked():
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.LOGIN_FAILED,
                severity=SecurityEvent.Severity.MEDIUM,
                user=user,
            )
            CompromiseDetectionService.evaluate_user(user)

            raise PermissionDenied(f"Account is locked.")

        if hasattr(user, "is_compromised") and user.is_compromised:
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.LOGIN_FAILED,
                severity=SecurityEvent.Severity.MEDIUM,
                user=user,
            )

            raise PermissionDenied("Account under review")

        return super().user_can_authenticate(user)
