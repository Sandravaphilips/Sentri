from logs.constants import AuditEvent
from logs.services.audit import AuditService


class APIKeyAuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        api_key = getattr(request, "api_key", None)

        if api_key is not None:
            status = response.status_code

            if status < 400:
                action = AuditEvent.API_KEY_USED
            else:
                action = AuditEvent.APi_KEY_DENIED

            AuditService.log_audit_event(
                request=request,
                user=request.user if request.user.is_authenticated else None,
                action=action,
                status_code=status,
                metadata={"api_key_id": str(api_key.id)},
            )

        return response
