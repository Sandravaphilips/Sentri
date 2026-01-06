from datetime import timedelta

API_KEY_RATE_LIMITS = {
    "default": {
        "requests": 100,
        "window": timedelta(minutes=1),
    }
}
