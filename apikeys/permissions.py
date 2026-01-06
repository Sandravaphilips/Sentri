from rest_framework.permissions import BasePermission


class HasAPIKeyScope(BasePermission):
    """
    Enforces API key scopes on views.

    Usage:
        required_scopes = ["read:events"]
    """

    def has_permission(self, request, view):
        required_scopes = getattr(view, "required_scopes", None)

        if not required_scopes:
            return True

        if not hasattr(request, "api_key"):
            return True

        api_key = request.api_key

        return all(scope in api_key.scopes for scope in required_scopes)
