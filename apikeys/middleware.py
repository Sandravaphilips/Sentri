from rest_framework.response import Response
from rest_framework import status

from apikeys.services.rate_limit import APIKeyRateLimitService
from logs.constants import AuditEvent
from logs.services.audit import AuditService


class APIKeyRateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        api_key = getattr(request, "api_key", None)

        if api_key:
            allowed = APIKeyRateLimitService.is_allowed(api_key)

            if not allowed:
                AuditService.log_audit_event(
                    request=request,
                    user=request.user,
                    action=AuditEvent.API_KEY_RATE_LIMITED,
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    metadata={"api_key_id": str(api_key.id)},
                )

                return Response(
                    {"detail": "API key rate limit exceeded."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

        return self.get_response(request)
