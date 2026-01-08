from rest_framework.permissions import BasePermission

from security.models import SecurityEvent
from security.services import SecurityEventService


class HasAPIKeyScope(BasePermission):
    """
    Enforces API key scopes on views.

    Usage:
        required_scopes = ["read:events"]
    """

    def has_permission(self, request, view):
        api_key = getattr(request, "api_key", None)
        required_scope = getattr(view, "required_scope", None)

        if not required_scope or not api_key:
            return True

        if required_scope not in api_key.scopes:
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.SCOPE_VIOLATION,
                severity=SecurityEvent.Severity.HIGH,
                user=request.user,
                api_key=api_key,
                request=request,
                metadata={
                    "required_scope": required_scope,
                    "key_scopes": api_key.scopes,
                    "path": request.path,
                },
            )
            return False

        return True
