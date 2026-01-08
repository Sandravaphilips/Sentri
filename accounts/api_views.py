from django.contrib.auth import get_user_model
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from rest_framework.exceptions import AuthenticationFailed, ValidationError
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView, TokenObtainPairView

from accounts.serializers import SignupSerializer, LoginSerializer
from accounts.services import AccountSecurityService
from logs.constants import AuditEvent
from logs.services import AuditService
from security.models import SecurityEvent
from security.services import CompromiseDetectionService
from security.services import SecurityEventService

User = get_user_model()


@method_decorator(
    ratelimit(key="ip", rate="5/m", block=True),
    name="dispatch"
)
class APISignupView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    serializer_class = SignupSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if not serializer.is_valid():
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.SIGNUP_FAILED,
                severity=SecurityEvent.Severity.LOW,
                request=request,
                metadata={
                    "errors": list(serializer.errors.keys()),
                },
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()

        AuditService.log_audit_event(
            request=request,
            user=user,
            action=AuditEvent.SIGNUP_SUCCESS,
            status_code=status.HTTP_201_CREATED,
        )

        return Response(
            {"detail": "User created successfully"},
            status=status.HTTP_201_CREATED,
        )


@method_decorator(csrf_exempt, name="dispatch")
class APILoginView(TokenObtainPairView):
    authentication_classes = []
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        user = User.objects.filter(email=email).first()

        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except (AuthenticationFailed, ValidationError) as exc:
            SecurityEventService.emit(
                event_type=SecurityEvent.EventType.LOGIN_FAILED,
                severity=SecurityEvent.Severity.MEDIUM,
                user=user,
                request=request,
                metadata={"reason": exc.__class__.__name__},
            )

            if user:
                AccountSecurityService.record_failed_login(user, request)
                CompromiseDetectionService.evaluate_user(user)

            raise exc

        AccountSecurityService.record_successful_login(user, request)

        response = super().post(request, *args, **kwargs)

        tokens = response.data

        response = Response(
            {"detail": "User logged in successfully"},
            status=status.HTTP_200_OK,
        )

        response.set_cookie(
            key="access_token",
            value=tokens["access"],
            httponly=True,
            secure=True,
            samesite="Lax",
        )

        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh"],
            httponly=True,
            secure=True,
            samesite="Lax",
        )

        return response


class PublicTokenRefreshView(TokenRefreshView):
    permission_classes = [AllowAny]


class PublicTokenVerifyView(TokenVerifyView):
    permission_classes = [AllowAny]
