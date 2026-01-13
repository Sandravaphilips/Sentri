from django.core.cache import cache
from django.utils import timezone
from apikeys.limits import API_KEY_RATE_LIMITS


class APIKeyRateLimitService:
    @staticmethod
    def get_cache_key(api_key_id):
        return f"rate_limit:api_key:{api_key_id}"

    @staticmethod
    def is_allowed(api_key):
        policy = API_KEY_RATE_LIMITS["default"]
        cache_key = APIKeyRateLimitService.get_cache_key(api_key.id)

        data = cache.get(cache_key)

        now = timezone.now()

        if not data or now > data["reset_at"]:
            cache.set(
                cache_key,
                {
                    "count": 1,
                    "reset_at": now + policy["window"],
                },
                timeout=int(policy["window"].total_seconds()),
            )
            return True

        if data["count"] >= policy["requests"]:
            return False

        data["count"] += 1
        cache.set(
            cache_key,
            data,
            timeout=int((data["reset_at"] - now).total_seconds()),
        )

        return True
