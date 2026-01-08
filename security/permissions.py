from rest_framework.permissions import BasePermission


class IsNotCompromised(BasePermission):
    """
    Denies access if the authenticated user is flagged as compromised.
    """

    message = "Account is under security review."

    def has_permission(self, request, view):
        user = request.user

        if not user or not user.is_authenticated:
            return False

        return not user.is_compromised
