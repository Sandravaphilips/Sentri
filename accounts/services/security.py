from datetime import timedelta

from django.utils import timezone
from rest_framework import status

from logs.constants import AuditEvent
from logs.services.audit import AuditService

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
        user.failed_login_attempts += 1

        if user.failed_login_attempts >= MAX_ATTEMPTS:
            user.account_locked_until = timezone.now() + LOCK_DURATION

        user.save(update_fields=[
            "failed_login_attempts",
            "account_locked_until",
        ])

        AuditService.log_audit_event(
            request=request,
            user=user,
            action=AuditEvent.LOGIN_FAILED,
            status_code=status.HTTP_401_UNAUTHORIZED,
            metadata={
                "failed_attempts": user.failed_login_attempts,
                "locked": user.is_account_locked(),
            },
        )

        if user.is_account_locked():
            AuditService.log_audit_event(
                request=request,
                user=user,
                action=AuditEvent.ACCOUNT_LOCKED,
                status_code=status.HTTP_403_FORBIDDEN,
            )
