from django.utils import timezone
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

from security.models import SecurityEvent
from security.services import SecurityEventService


class CookieJWTAuthentication(JWTAuthentication):
    access_cookie_name = "access_token"

    def authenticate(self, request):
        raw_token = request.COOKIES.get(self.access_cookie_name)

        if raw_token is None:
            return None

        try:
            validated_token = self.get_validated_token(raw_token)
            user = self.get_user(validated_token)
        except Exception:
            raise AuthenticationFailed("Invalid or expired token")

        if user.account_locked_until and user.account_locked_until <= timezone.now():
            user.account_locked_until = None
            user.failed_login_attempts = 0
            user.save(update_fields=["account_locked_until", "failed_login_attempts"])

            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.ACCOUNT_UNLOCKED,
                severity=SecurityEvent.Severity.LOW,
                user=user,
                request=request,
                metadata={"reason": "lock_expired"},
            )

        return user, validated_token
