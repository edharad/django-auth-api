import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from asgiref.sync import sync_to_async
from ..serializers import UserSerializer
from ..models import User

logger = logging.getLogger(__name__)  # Création du logger

# 🔹 Vue pour obtenir les détails de l'utilisateur authentifié
class GetUserDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)

# 🔹 Vue pour mettre à jour les détails de l'utilisateur authentifié
class UpdateUserDetailsView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            logger.info(f"User {user.username} updated their profile successfully")
            return Response(serializer.data)

        logger.warning(f"Failed update attempt for user: {user.username}")
        return Response(serializer.errors, status=400)

# 🔹 Vue pour supprimer le compte de l'utilisateur authentifié
class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        user = request.user
        username = user.username

        user.delete()
        logger.info(f"User {username} deleted their account")
        return Response({"message": "User account deleted"})
