import hmac
import hashlib
import secrets
from django.conf import settings
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied

from apikeys.models import APIKey
from logs.constants import AuditEvent
from logs.services import AuditService
from security.models import SecurityEvent
from security.services import SecurityEventService


class APIKeyService:
    KEY_PREFIX = "sk_"

    @staticmethod
    def generate_raw_key():
        return f"{APIKeyService.KEY_PREFIX}{secrets.token_urlsafe(32)}"

    @staticmethod
    def hash_key(raw_key):
        return hmac.new(
            key=settings.SECRET_KEY.encode(),
            msg=raw_key.encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def create_key(*, user, name, scopes, expires_at=None):
        if user.is_compromised:
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.API_KEY_CREATION_BLOCKED,
                severity=SecurityEvent.Severity.HIGH,
                user=user,
                metadata={"reason": "account_compromised"},
            )
            raise PermissionDenied("Account under security review.")

        raw_key = APIKeyService.generate_raw_key()
        key_hash = APIKeyService.hash_key(raw_key)

        api_key = APIKey.objects.create(
            user=user,
            name=name,
            key_hash=key_hash,
            scopes=scopes,
            expires_at=expires_at,
        )

        AuditService.log_audit_event(
            user=user,
            action=AuditEvent.API_KEY_CREATED,
            api_key=api_key,
            metadata={
                "scopes": api_key.scopes,
                "expires_at": api_key.expires_at.isoformat() if api_key.expires_at else None,
            },
        )

        return api_key, raw_key

    @staticmethod
    def revoke_key(*, api_key, reason=None):
        if api_key.user.is_compromised:
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.API_KEY_REVOCATION_BLOCKED,
                severity=SecurityEvent.Severity.HIGH,
                user=api_key.user,
                api_key=api_key,
                metadata={"reason": "account_compromised"},
            )
            raise PermissionDenied("Account under security review.")

        if api_key.is_revoked:
            return

        api_key.is_revoked = True
        api_key.revoked_at = timezone.now()
        api_key.save(update_fields=["is_revoked", "revoked_at"])

        AuditService.log_audit_event(
            user=api_key.user,
            action=AuditEvent.API_KEY_REVOKED,
            api_key=api_key,
            metadata={"reason": reason},
        )

        SecurityEventService.emit(
            event_type=SecurityEvent.EventType.API_KEY_REVOKED,
            severity=SecurityEvent.Severity.HIGH,
            user=api_key.user,
            api_key=api_key,
            metadata={"reason": reason},
        )
