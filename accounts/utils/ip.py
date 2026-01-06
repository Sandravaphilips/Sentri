from django.conf import settings


def get_client_ip(request):
    remote_addr = request.META.get("REMOTE_ADDR")

    if remote_addr in settings.ALLOWED_HOSTS:
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()

    return remote_addr
