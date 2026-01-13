from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import gettext_lazy as _

from security.models import SecurityEvent
from security.services import SecurityEventService, CompromiseDetectionService


class APIKeyAuthentication(BaseAuthentication):
    keyword = "Api-Key"

    def authenticate(self, request):

        from apikeys.models import APIKey
        from apikeys.services import APIKeyService

        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return None

        try:
            keyword, raw_key = auth_header.split()
        except ValueError:
            raise AuthenticationFailed(_("Invalid Authorization header format."))

        if keyword != self.keyword:
            return None

        if not raw_key:
            raise AuthenticationFailed(_("API key missing."))

        key_hash = APIKeyService.hash_key(raw_key)

        try:
            api_key = APIKey.objects.select_related("user").get(
                key_hash=key_hash,
            )
        except APIKey.DoesNotExist:
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.API_KEY_AUTH_FAILED,
                severity=SecurityEvent.Severity.MEDIUM,
                request=request,
                metadata={"reason": "unknown_key"},
            )

            raise AuthenticationFailed(_("Invalid API key."))

        if api_key.is_revoked:
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.API_KEY_AUTH_FAILED,
                severity=SecurityEvent.Severity.CRITICAL,
                user=api_key.user,
                api_key=api_key,
                request=request,
                metadata={"reason": "key_revoked"},
            )

            CompromiseDetectionService.evaluate_user(api_key.user)

            raise AuthenticationFailed("API key revoked.")

        if api_key.expires_at and api_key.expires_at < timezone.now():
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.API_KEY_AUTH_FAILED,
                severity=SecurityEvent.Severity.HIGH,
                user=api_key.user,
                api_key=api_key,
                request=request,
                metadata={"reason": "key_expired"},
            )

            CompromiseDetectionService.evaluate_user(api_key.user)

            raise AuthenticationFailed("API key expired.")

        user = api_key.user

        if user.is_compromised:
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.API_KEY_AUTH_FAILED,
                severity=SecurityEvent.Severity.CRITICAL,
                user=user,
                api_key=api_key,
                request=request,
                metadata={"reason": "user_compromised"},
            )

            raise AuthenticationFailed(_("Account under security review."))

        if user.is_account_locked():
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.API_KEY_AUTH_FAILED,
                severity=SecurityEvent.Severity.CRITICAL,
                user=user,
                api_key=api_key,
                request=request,
                metadata={"reason": "account_locked"},
            )

            raise AuthenticationFailed(_("Account temporarily locked."))

        request.api_key = api_key

        return user, api_key
