import hmac
import hashlib
import secrets
from django.conf import settings
from apikeys.models import APIKey


class APIKeyService:
    """
    Service responsible for API key generation and hashing.
    """

    KEY_PREFIX = "sk_"  # Helps identify key type quickly

    @staticmethod
    def generate_raw_key():
        """
        Generates a cryptographically secure raw API key.
        Returned value is shown ONCE to the user.
        """
        return f"{APIKeyService.KEY_PREFIX}{secrets.token_urlsafe(32)}"

    @staticmethod
    def hash_key(raw_key):
        """
        Hashes the API key using HMAC-SHA256.
        The raw key is never stored.
        """
        return hmac.new(
            key=settings.SECRET_KEY.encode(),
            msg=raw_key.encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def create_key(*, user, name, scopes):
        """
        Creates a new API key for a user.

        Returns:
            (api_key_instance, raw_key)
        """
        raw_key = APIKeyService.generate_raw_key()
        key_hash = APIKeyService.hash_key(raw_key)

        api_key = APIKey.objects.create(
            user=user,
            name=name,
            key_hash=key_hash,
            scopes=scopes,
        )

        return api_key, raw_key
