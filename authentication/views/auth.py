import logging
from rest_framework import generics, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from ..models import User
from ..serializers import RegisterSerializer

logger = logging.getLogger(__name__)  # Création du logger

# 🔹 Vue pour l'inscription des utilisateurs
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]  # Accessible à tout le monde

# 🔹 Vue pour la connexion des utilisateurs
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        password = request.data.get("password")

        if not username or not password:
            return Response({"error": "Username and password are required"}, status=400)


        user = authenticate(username=username, password=password)

        if user:
            refresh = RefreshToken.for_user(user)
            logger.info(f"User {username} logged in successfully")  # ✅ Log de succès
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            })

        logger.warning(f"Failed login attempt for user: {username}")  # 🚨 Log en cas d'échec
        return Response({"error": "Invalid Credentials"}, status=401)

# 🔹 Vue pour la déconnexion des utilisateurs (révocation du token)
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get("refresh")

            if not refresh_token:
                return Response({"error": "Refresh token is required"}, status=400)

            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(f"User {request.user.username} logged out successfully")  # ✅ Log de succès
            return Response({"message": "Successfully logged out"}, status=200)

        except Exception as e:
                    return Response({"error": "Invalid token"}, status=400)


