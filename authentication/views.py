import onfido # Importe le SDK Onfido pour interagir avec l'API Onfido
import logging # Importe le module logging pour enregistrer les messages de journalisation
import uuid # Importe le module uuid pour générer des codes uniques
from django.conf import settings # Importe les paramètres de configuration de Django
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str 
from rest_framework import generics, permissions # Importe les classes generics et permissions de rest_framework
from rest_framework.permissions import IsAuthenticated # Importe la classe IsAuthenticated pour vérifier si l'utilisateur est authentifié
from rest_framework.response import Response # Import la classe Response pour retourner des réponses HTTP
from rest_framework_simplejwt.tokens import RefreshToken # Importe la classe Token pour générer des tokens d'authentification
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView # Importe la classe TokenObtainPairView pour obtenir des tokens d'authentification
from rest_framework.views import APIView # Importe la classe APIView pour créer des vues basées sur des classes 
from django.contrib.auth import authenticate # Importe la fonction authenticate pour vérifier les informations d'identification
from .models import User # Importe le modèle User
from .serializers import UserSerializer, RegisterSerializer # Importe les sérialiseurs UserSerializer et RegisterSerializer
from django.core.mail import send_mail # Importe la fonction send_mail pour envoyer des e-mails

logger = logging.getLogger(__name__) # Crée un objet logger pour enregistrer les messages de journalisation

# Vue pour révoquer les tokens JWT lors de la déconnexion
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  # Vérifie si l'utilisateur est authentifié

    def post(self, request, *args, **kwargs):
        try:
            # Récupère le refresh token depuis la requête
            refresh_token = request.data.get('refresh')  
            
            if not refresh_token:
                return Response({'error': 'Refresh token is required'}, status=400)

            # Blackliste le token pour qu'il ne soit plus utilisable
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({'message': 'Successfully logged out'}, status=200)  # Réponse de succès
        except Exception as e:
            return Response({'error': 'Invalid token'}, status=400)  # Réponse en cas d'échec

# Vue pour envoyer le code de validation par email
class SendVerificationCodeView(APIView):
    permission_classes = [permissions.IsAuthenticated] # Vérifie si l'utilisateur est authentifié

    def post(self, request, *args, **kwargs):
        user = request.user # Récupère l'utilisateur authentifié
        verification_code = user.email_verification_code # Récupère le code de validation de l'e-mail de l'utilisateur
        send_mail(
            'Email Verification', # Sujet de l'e-mail
            f'Your verification code is: {verification_code}', # Corps de l'e-mail avec le code de validation
            settings.DEFAULT_FROM_EMAIL, # Adresse e-mail de l'expéditeur
            [user.email], # Adresse e-mail du destinataire
            fail_silently=False, # Ne pas échouer silencieusement en cas d'erreur
        )
        print(f"Verification code for user {user.username}: {verification_code}")
        return Response({'message': 'Verification code sent to your email.'}) # Retourne un message de succès

# Vue pour regenerer le code de validation par email
class ResendVerificationCodeView(APIView):
    permission_classes = [permissions.IsAuthenticated] # Vérifie si l'utilisateur est authentifié

    def post(self, request, *args, **kwargs):
        user = request.user
        user.email_verification_code = uuid.uuid4()
        user.save()
        send_mail(
            'Email Verification', # Sujet de l'e-mail
            f'Your new verification code is: {user.email_verification_code}', # Corps de l'e-mail avec le code de validation
            settings.DEFAULT_FROM_EMAIL, # Adresse e-mail de l'expéditeur
            [user.email], # Adresse e-mail du destinataire
            fail_silently=False, # Ne pas échouer silencieusement en cas d'erreur
        )
        logger.info(f"New verification code for user {user.username}: {user.email_verification_code}")
        return Response({'message': 'New verification code sent to your email.'}) # Retourne un message de succès


# Vue pour vérifier le code de validation de l'e-mail
class VerifyEmailView(APIView):
    permission_classes = [permissions.IsAuthenticated] # Vérifie si l'utilisateur est authentifié

    def post(self, request, *args, **kwargs):
        user = request.user # Récupère l'utilisateur authentifié
        verification_code = request.data.get('verification_code') # Récupère le code de validation de l'e-mail de la requête
        if str(verification_code) == str(user.email_verification_code): # Si le code de validation est correct
            user.email_verified = True # Marque l'e-mail de l'utilisateur comme vérifié
            user.save() # Enregistre les modifications de l'utilisateur
            return Response({'message': 'Email verified successfully'}) # Retourne un message de vérification réussie
        logger.warning(f'Failed email verification attempt for user: {user.username}') # Enregistre un message de journalisation en cas d'échec de la vérification
        return Response({'error': 'Invalid verification code'}, status=400) # Retourne une erreur si le code de validation est incorrect

# Vue pour créer une vérification d'identité avec Onfido
class CreateOnfidoCheckView(APIView):
    permission_classes = [IsAuthenticated] # Vérifie si l'utilisateur est authentifié

    def post(self, request, *args, **kwargs):
        user = request.user # Récupère l'utilisateur authentifié
        onfido.api_key = settings.ONFIDO_API_KEY # Définit la clé API Onfido à partir des paramètres de configuration
        applicant = onfido.Applicant.create( # Crée un demandeur Onfido
            first_name=user.first_name, # Utilise le prénom de l'utilisateur comme prénom du demandeur
            last_name=user.last_name, # Utilise le nom de l'utilisateur comme nom du demandeur
            email=user.email, # Utilise l'e-mail de l'utilisateur comme e-mail du demandeur
        )
        check = onfido.Check.create( # Crée une vérification Onfido
            type='express', # Utilise le type de vérification express
            reports=[{'name': 'identity'}], # Inclut un rapport d'identité dans la vérification
            applicant_id=applicant.id, # Utilise l'ID du demandeur pour la vérification
        )
        return Response({'check_id': check.id}) # Retourne l'ID de la vérification Onfido
    
# Vue pour obtenir le statut de la vérification Onfido
class GetOnfidoCheckStatusView(APIView):
    permission_classes = [IsAuthenticated] # Vérifie si l'utilisateur est authentifié

    def get(self, request, *args, **kwargs):
        check_id = request.query_params.get('check_id') # Récupère l'ID de la vérification Onfido à partir des paramètres de requête
        onfido.api_key = settings.ONFIDO_API_KEY # Définit la clé API Onfido à partir des paramètres de configuration
        check = onfido.Check.find(check_id) # Récupère la vérification Onfido à partir de l'ID
        return Response({'status': check.status}) # Retourne le statut de la vérification Onfido

# Vue pour obtenir les détails de l'utilisateur authentifié
class GetUserDetailsView(APIView):
    permission_classes = [IsAuthenticated] # Vérifie si l'utilisateur est authentifié

    def get(self, request, *args, **kwargs):
        user = request.user # Récupère l'utilisateur authentifié
        serializer = UserSerializer(user) # Sérialise les détails de l'utilisateur
        return Response(serializer.data) # Retourne les détails de l'utilisateur

# Vue pour mettre à jour les détails de l'utilisateur authentifié
class UpdateUserDetailsView(APIView):
    permission_classes = [IsAuthenticated] # Vérifie si l'utilisateur est authentifié

    def put(self, request, *args, **kwargs):
        user = request.user # Récupère l'utilisateur authentifié
        serializer = UserSerializer(user, data=request.data, partial=True) # Sérialise les données de la requête pour mettre à jour l'utilisateur
        if serializer.is_valid(): # Si les données sont valides
            serializer.save() # Enregistre les modifications de l'utilisateur
            return Response(serializer.data) # Retourne les détails de l'utilisateur mis à jour
        logger.warning(f'Failed update attempt for user: {user.username}')
        return Response(serializer.errors, status=400) # Retourne les erreurs de validation si les données ne sont pas valides

# Vue pour envoyer la requête de réinitialisation du mot de passe
class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny] # Permet à tout le monde d'accéder à cette vue

    def post(self, request, *args, **kwargs):
        email = request.data.get('email') # Récupère l'e-mail de la requête
        user = User.objects.filter(email=email).first()
        if user:
            token_generator = PasswordResetTokenGenerator() # Génère un jeton de réinitialisation du mot de passe
            token = token_generator.make_token(user) # Crée un jeton pour l'utilisateur
            uid = urlsafe_base64_encode(force_bytes(user.pk)) # Encode l'ID de l'utilisateur en base64
            reset_url = f'{settings.FRONTEND_URL}/reset-password/{uid}/{token}' # URL pour réinitialiser le mot de passe
            send_mail(
                'Password Reset Request', # Sujet de l'e-mail
                f'Click the link to reset your password: {reset_url}', # Corps de l'e-mail avec le lien de réinitialisation
                settings.DEFAULT_FROM_EMAIL, # Adresse e-mail de l'expéditeur
                [user.email], # Adresse e-mail du destinataire
                fail_silently=False, # Ne pas échouer silencieusement en cas d'erreur
            )
            logger.info(f'Password reset link sent to {user.email}')
            return Response({'message': 'Password reset link sent to your email'})

# Vue pour réinitialiser le mot de passe
class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny] # Permet à tout le monde d'accéder à cette vue

    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64)) # Décode l'ID de l'utilisateur en base
            user = User.objects.get(pk=uid) # Récupère l'utilisateur à partir de l'ID
        except (TypeError, ValueError, OverflowError, User.DoesNotExist): # En cas d'erreur
            user = None

        token_generator = PasswordResetTokenGenerator()
        if user and token_generator.check_token(user, token):
            password = request.data.get('password')
            user.set_password(password)
            user.save()
            logger.info(f'Password reset for user: {user.username}')
            return Response({'message': 'Password reset successful'})
        logger.warning(f'Failed password reset attempt for user: {user.username}')
        return Response({'error': 'Invalid reset link'}, status=400)

# Vue pour supprimer le compte de l'utilisateur authentifié
class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated] # Vérifie si l'utilisateur est authentifié

    def post(self, request, *args, **kwargs):
        user = request.user # Récupère l'utilisateur authentifié
        user.delete() # Supprime l'utilisateur
        return Response({'message': 'User account deleted'}) # Retourne un message de suppression de compte réussie

