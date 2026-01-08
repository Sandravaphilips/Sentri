from django.utils import timezone

from logs.constants import AuditEvent
from security.services import SecurityEventService
from security.models import SecurityEvent
from logs.services import AuditService
from apikeys.models import APIKey


class RemediationService:
    """
    Handles explicit security remediation actions.
    """

    @staticmethod
    def unlock_account(*, user, reason=None):
        """
        Unlock a locked user account.
        """

        if not user.is_account_locked():
            return

        user.account_locked_until = None
        user.failed_login_attempts = 0
        user.save(update_fields=[
            "account_locked_until",
            "failed_login_attempts",
        ])

        AuditService.log_audit_event(
            user=user,
            action=AuditEvent.ACCOUNT_UNLOCKED,
            metadata={"reason": reason},
        )

        SecurityEventService.emit(
            event_type=SecurityEvent.EventType.REMEDIATION_APPLIED,
            severity=SecurityEvent.Severity.MEDIUM,
            user=user,
            metadata={"action": "unlock_account"},
        )

    @staticmethod
    def clear_compromise(
        *,
        user,
        reason=None,
    ):
        """
        Clear compromised state after remediation.
        """

        if not user.is_compromised:
            return

        user.is_compromised = False
        user.compromise_reason = ""
        user.compromised_at = None
        user.save(update_fields=[
            "is_compromised",
            "compromise_reason",
            "compromised_at",
        ])

        AuditService.log_audit_event(
            user=user,
            action=AuditEvent.COMPROMISE_CLEARED,
            metadata={"reason": reason},
        )

        SecurityEventService.emit(
            event_type=SecurityEvent.EventType.REMEDIATION_APPLIED,
            severity=SecurityEvent.Severity.MEDIUM,
            user=user,
            metadata={"action": "clear_compromise"},
        )

    @staticmethod
    def revoke_all_api_keys(
        *,
        user,
        reason,
    ):
        """
        Revoke all active API keys for a user.
        Returns number of revoked keys.
        """

        keys = APIKey.objects.filter(
            user=user,
            is_revoked=False,
        )

        revoked_count = 0

        for key in keys:
            key.is_revoked = True
            key.revoked_at = timezone.now()
            key.save(update_fields=["is_revoked", "revoked_at"])
            revoked_count += 1

        AuditService.log_audit_event(
            user=user,
            action=AuditEvent.ALL_API_KEYS_REVOKED,
            metadata={
                "count": revoked_count,
                "reason": reason,
            },
        )

        SecurityEventService.emit(
            event_type=SecurityEvent.EventType.REMEDIATION_APPLIED,
            severity=SecurityEvent.Severity.HIGH,
            user=user,
            metadata={
                "action": "revoke_all_api_keys",
                "count": revoked_count,
            },
        )

        return revoked_count
