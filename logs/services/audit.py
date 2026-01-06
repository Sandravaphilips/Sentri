from logs.models import AuditLog
from accounts.utils.ip import get_client_ip


class AuditService:
    @staticmethod
    def log_audit_event(
        *,
        request,
        action,
        user=None,
        api_key=None,
        status_code=200,
        metadata=None,
    ):
        AuditLog.objects.create(
            user=user,
            api_key_id=api_key.id if api_key else None,
            action=action,
            path=request.path if request else "",
            method=request.method if request else "",
            status_code=status_code,
            ip_address=get_client_ip(request) if request else None,
            user_agent=request.META.get("HTTP_USER_AGENT", "")[:255] if request else "",
            metadata=metadata or {},
        )
