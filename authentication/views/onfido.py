import logging
import onfido
from asgiref.sync import sync_to_async
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

logger = logging.getLogger(__name__)  # Création du logger

# 🔹 Vue pour créer une vérification d'identité avec Onfido
class CreateOnfidoCheckView(APIView):
    permission_classes = [IsAuthenticated]  # ✅ L'utilisateur doit être connecté

    def post(self, request, *args, **kwargs):
        user = request.user

        try:
            check = self._create_onfido_check_async(user)
            logger.info(f"Onfido check created for user: {user.username}")
            return Response({"check_id": check.id})

        except Exception as e:
            logger.error(f"Onfido verification failed for user {user.username}: {str(e)}")
            return Response({"error": "Onfido verification failed", "details": str(e)}, status=500)

    def _create_onfido_check_async(self, user):
        """Appelle l'API Onfido en mode asynchrone"""
        onfido_api = onfido.Api(settings.ONFIDO_API_KEY)

        applicant = onfido_api.Applicant.create(
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
        )

        check = onfido_api.Check.create(
            type="express",
            reports=[{"name": "identity"}],
            applicant_id=applicant.id,
        )

        return check

# 🔹 Vue pour obtenir le statut de la vérification Onfido
class GetOnfidoCheckStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        check_id = request.query_params.get("check_id")

        if not check_id:
            return Response({"error": "Check ID is required"}, status=400)

        try:
            check_status = self._get_onfido_status_async(check_id)
            logger.info(f"Onfido check status retrieved for check_id: {check_id}")
            return Response({"status": check_status})

        except Exception as e:
            logger.error(f"Failed to retrieve Onfido check status for check_id {check_id}: {str(e)}")
            return Response({"error": "Failed to retrieve Onfido check status", "details": str(e)}, status=500)

    async def _get_onfido_status_async(self, check_id):
        """Récupère le statut de vérification Onfido en mode asynchrone"""
        onfido_api = onfido.Api(settings.ONFIDO_API_KEY)
        check = onfido_api.Check.find(check_id)
        return check.status

