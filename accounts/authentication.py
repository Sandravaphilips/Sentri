from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed


class CookieJWTAuthentication(JWTAuthentication):
    """
    Authenticate using JWT stored in an HTTP-only cookie.
    """

    access_cookie_name = "access_token"

    def authenticate(self, request):
        raw_token = request.COOKIES.get(self.access_cookie_name)

        if raw_token is None:
            return None

        try:
            validated_token = self.get_validated_token(raw_token)
            user = self.get_user(validated_token)
        except Exception:
            raise AuthenticationFailed("Invalid or expired token")

        return user, validated_token
