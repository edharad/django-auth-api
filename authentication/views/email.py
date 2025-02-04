import logging
import uuid
from asgiref.sync import sync_to_async
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from ..models import User

logger = logging.getLogger(__name__)  # Création du logger

# 🔹 Vue pour envoyer le code de validation par email
class SendVerificationCodeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        verification_code = user.email_verification_code

        try:
            self._send_email(user.email, verification_code)
            logger.info(f"Verification code sent to {user.email}")
            return Response({"message": "Verification code sent to your email."})
        except Exception as e:
            logger.error(f"Failed to send verification email: {str(e)}")
            return Response({"error": "Failed to send verification email"}, status=500)

    def _send_email(self, email, verification_code):
        """Envoie l'email de vérification en mode asynchrone"""
        send_mail(
            "Email Verification",
            f"Your verification code is: {verification_code}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

# 🔹 Vue pour renvoyer un nouveau code de vérification par email
class ResendVerificationCodeView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        user.email_verification_code = uuid.uuid4()
        user.save()

        try:
            self._send_email(user.email, user.email_verification_code)
            logger.info(f"New verification code sent to {user.email}")
            return Response({"message": "New verification code sent to your email."})
        except Exception as e:
            logger.error(f"Failed to resend verification email: {str(e)}")
            return Response({"error": "Failed to resend verification email"}, status=500)

    def _send_email(self, email, verification_code):
        """Envoie l'email en mode asynchrone"""
        send_mail(
            "Email Verification",
            f"Your new verification code is: {verification_code}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

# 🔹 Vue pour vérifier le code de validation de l'email
class VerifyEmailView(APIView):
    permission_classes = [IsAuthenticated]  # ✅ L'utilisateur doit être connecté

    def post(self, request, *args, **kwargs):
        user = request.user
        verification_code = request.data.get("verification_code")

        if not verification_code:
            logger.warning(f"Email verification attempt without a code for user: {user.username}")
            return Response({"error": "Verification code is required"}, status=400)

        try:
            if str(verification_code) == str(user.email_verification_code):  # ✅ Vérification correcte
                if user.email_verified:
                    logger.info(f"User {user.username} attempted to verify an already verified email.")
                    return Response({"message": "Email is already verified"}, status=200)

                user.email_verified = True
                user.is_verified = True
                user.save()
                logger.info(f"User {user.username} successfully verified their email.")  # 🔹 Log de succès
                return Response({"message": "Email verified successfully"})

            logger.warning(f"Failed email verification attempt for user: {user.username}")  # 🔹 Log d’échec
            return Response({"error": "Invalid verification code"}, status=400)

        except Exception as e:
            logger.error(f"Unexpected error in email verification: {str(e)}")  # 🔹 Log d’erreur
            return Response({"error": "An error occurred while verifying the email"}, status=500)
