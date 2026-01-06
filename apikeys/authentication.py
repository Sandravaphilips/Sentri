from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils.translation import gettext_lazy as _


class APIKeyAuthentication(BaseAuthentication):
    """
    Authenticate requests using an API key.

    Expected header:
        Authorization: Api-Key <key>
    """

    keyword = "Api-Key"

    def authenticate(self, request):

        from apikeys.models import APIKey
        from apikeys.services.api_key import APIKeyService

        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return None

        try:
            keyword, raw_key = auth_header.split()
        except ValueError:
            raise AuthenticationFailed(_("Invalid Authorization header format."))

        if keyword != self.keyword:
            return None

        if not raw_key:
            raise AuthenticationFailed(_("API key missing."))

        key_hash = APIKeyService.hash_key(raw_key)

        try:
            api_key = APIKey.objects.select_related("user").get(
                key_hash=key_hash,
                is_revoked=False,
            )
        except APIKey.DoesNotExist:
            raise AuthenticationFailed(_("Invalid or revoked API key."))

        user = api_key.user

        if user.is_compromised:
            raise AuthenticationFailed(_("Account under security review."))

        if user.is_account_locked():
            raise AuthenticationFailed(_("Account temporarily locked."))

        request.api_key = api_key

        return user, api_key
