TRUSTED_PROXIES = {"127.0.0.1"}


def get_client_ip(request):
    remote_addr = request.META.get("REMOTE_ADDR")

    if remote_addr in TRUSTED_PROXIES:
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            return xff.split(",")[0].strip()

    return remote_addr
