from django.contrib.auth import get_user_model
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView, TokenObtainPairView

from accounts.serializers import SignupSerializer, LoginSerializer
from accounts.services import AccountSecurityService

User = get_user_model()


@method_decorator(
    ratelimit(key="ip", rate="5/m", block=True),
    name="dispatch"
)
class APISignupView(APIView):
    permission_classes = [AllowAny]
    serializer_class = SignupSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"detail": "User created successfully"},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name="dispatch")
class APILoginView(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        user = User.objects.filter(email=email).first()

        serializer = self.serializer_class(
            data={
                "email": email,
                "password": password,
            }
        )

        if not serializer.is_valid():
            if user:
                AccountSecurityService.record_failed_login(user, request)

            return JsonResponse(
                {"detail": "Invalid credentials"},
                status=401
            )

        AccountSecurityService.record_successful_login(user, request)

        tokens = serializer.validated_data
        response = Response(
                {"detail": "User logged in successfully"},
                status=status.HTTP_200_OK
            )

        response.set_cookie(
            key="access_token",
            value=tokens["access"],
            httponly=True,
            secure=True,
            samesite="Lax"
        )

        response.set_cookie(
            key="refresh_token",
            value=tokens["refresh"],
            httponly=True,
            secure=True,
            samesite="Lax"
        )

        return response


class PublicTokenRefreshView(TokenRefreshView):
    permission_classes = [AllowAny]


class PublicTokenVerifyView(TokenVerifyView):
    permission_classes = [AllowAny]
