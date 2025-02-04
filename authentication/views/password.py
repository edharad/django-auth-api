import logging
from asgiref.sync import sync_to_async
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from ..models import User

logger = logging.getLogger(__name__)  # Création du logger

# 🔹 Vue pour envoyer la requête de réinitialisation du mot de passe
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]  # ✅ Accessible à tout le monde

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        try:
            user = User.objects.get(email=email)
            token = PasswordResetTokenGenerator().make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            self._send_email(email, uid, token)

            logger.info(f"Password reset link sent to {user.email}")
            return Response({"message": "Password reset link sent to your email"})
        except User.DoesNotExist:
            logger.warning(f"Password reset attempted for non-existent email: {email}")
            return Response({"error": "User not found"}, status=404)

    def _send_email(self, email, uid, token):
        """Envoie l'email de réinitialisation en mode asynchrone"""
        reset_url = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}"
        send_mail(
            "Password Reset Request",
            f"Click the link to reset your password: {reset_url}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

# 🔹 Vue pour réinitialiser le mot de passe
class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]  # ✅ Accessible à tout le monde

    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            logger.warning(f"Invalid password reset attempt with uid: {uidb64}")
            return Response({"error": "Invalid reset link"}, status=400)

        token_generator = PasswordResetTokenGenerator()
        if token_generator.check_token(user, token):
            new_password = request.data.get("password")
            if not new_password or len(new_password) < 8:
                logger.warning(f"User {user.username} provided a weak password")
                return Response({"error": "Password must be at least 8 characters long"}, status=400)

            user.set_password(new_password)
            user.save()
            logger.info(f"Password reset successfully for user: {user.username}")
            return Response({"message": "Password reset successful"})

        logger.warning(f"Failed password reset attempt for user: {user.username}")
        return Response({"error": "Invalid reset link"}, status=400)

