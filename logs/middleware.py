from .models import APILog
import datetime

class APILoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.user.is_authenticated:
            APILog.objects.create(
                user=request.user,
                api_key=None,
                endpoint=request.path,
                ip_address=self.get_client_ip(request),
                method=request.method,
                status_code=response.status_code,
            )
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")
