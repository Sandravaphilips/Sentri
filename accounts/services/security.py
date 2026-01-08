from datetime import timedelta

from django.utils import timezone
from rest_framework import status

from logs.constants import AuditEvent
from logs.services.audit import AuditService
from security.models import SecurityEvent
from security.services.event import SecurityEventService

MAX_ATTEMPTS = 5
LOCK_DURATION = timedelta(minutes=15)


class AccountSecurityService:
    @staticmethod
    def record_successful_login(user, request):
        from accounts.utils.ip import get_client_ip

        user.last_login_ip = get_client_ip(request)
        user.last_login_user_agent = request.META.get("HTTP_USER_AGENT", "")[:255]
        user.last_login_at = timezone.now()
        user.failed_login_attempts = 0
        user.account_locked_until = None

        user.save(update_fields=[
            "last_login_ip",
            "last_login_user_agent",
            "last_login_at",
            "failed_login_attempts",
            "account_locked_until"
        ])

        AuditService.log_audit_event(
            request=request,
            user=user,
            action=AuditEvent.LOGIN_SUCCESS,
            status_code=status.HTTP_200_OK,
        )

    @staticmethod
    def record_failed_login(user, request):
        was_locked = user.is_account_locked()

        user.failed_login_attempts += 1

        if user.failed_login_attempts >= MAX_ATTEMPTS and not was_locked:
            user.account_locked_until = timezone.now() + LOCK_DURATION

            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.ACCOUNT_LOCKED,
                severity=SecurityEvent.Severity.HIGH,
                user=user,
                request=request,
                metadata={
                    "failed_attempts": user.failed_login_attempts,
                    "locked_until": user.account_locked_until.isoformat()
                },
            )

            AuditService.log_audit_event(
                request=request,
                user=user,
                action=AuditEvent.ACCOUNT_LOCKED,
                status_code=status.HTTP_403_FORBIDDEN,
                metadata={
                    "failed_attempts": user.failed_login_attempts,
                    "locked_until": user.account_locked_until.isoformat()
                },
            )

        user.save(update_fields=[
            "failed_login_attempts",
            "account_locked_until",
        ])
