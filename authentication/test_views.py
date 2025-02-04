from django.urls import reverse  # Importe la fonction reverse pour générer des URLs à partir des noms de vue
from rest_framework import status  # Importe les codes de statut HTTP de Django REST Framework
from rest_framework.test import APITestCase  # Importe la classe APITestCase pour écrire des tests d'API
from django.contrib.auth.tokens import PasswordResetTokenGenerator  # Importe la classe PasswordResetTokenGenerator pour générer des jetons de réinitialisation de mot de passe
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  # Importe les fonctions pour encoder et décoder les valeurs en base64
from django.utils.encoding import force_bytes, force_str # Importe les fonctions pour convertir les valeurs en octets et en chaînes
from .models import User  # Importe le modèle User
from rest_framework_simplejwt.tokens import RefreshToken  # Importe la classe RefreshToken pour générer des tokens d'actualisation
import uuid  # Importe le module UUID pour générer des codes uniques


# Classe de tests pour les vues d'authentification
class AuthenticationTests(APITestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpassword'
        )
        self.login_url = reverse('login')  # Génère l'URL pour la connexion
        self.register_url = reverse('register')  # Génère l'URL pour l'inscription
        self.send_verification_email_url = reverse('send_verification_code')  # Génère l'URL pour envoyer le code de validation par e-mail
        self.verify_email_url = reverse('verify_email')  # Génère l'URL pour vérifier le code de validation de l'e-mail

    # Test pour l'inscription des utilisateurs
    def test_register_user(self):
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpassword'
        }
        response = self.client.post(self.register_url, data, format='json')  # Envoie une requête POST à l'URL d'inscription
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)  # Vérifie que le code de statut est 201 Created
        self.assertEqual(User.objects.count(), 2)  # Vérifie qu'un utilisateur a été créé
        new_user = User.objects.get(username='newuser')
        self.assertEqual(new_user.email, 'newuser@example.com')  # Vérifie l'email de l'utilisateur
        self.assertFalse(new_user.email_verified)  # Vérifie que l'email n'est pas encore vérifié

    # Test pour la connexion des utilisateurs
    def test_login_user(self):
        data = {
            'username': 'testuser',
            'password': 'testpassword'
        }
        response = self.client.post(self.login_url, data, format='json')  # Envoie une requête POST à l'URL de connexion
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # Vérifie que le code de statut est 200 OK
        self.assertIn('access', response.data)  # Vérifie que la réponse contient un jeton d'accès
        self.assertIn('refresh', response.data)  # Vérifie que la réponse contient un jeton d'actualisation
        refresh_token = RefreshToken(response.data['refresh'])  # Vérifie la validité du jeton d'actualisation
        self.assertTrue(refresh_token.access_token)  # Vérifie que le jeton d'accès est valide

    # Test pour envoyer le code de validation par e-mail
    def test_send_verification_email(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.get_access_token()}')  # Ajoute le jeton d'accès à l'en-tête
        response = self.client.post(self.send_verification_email_url)  # Envoie une requête POST à l'URL d'envoi du code de validation
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # Vérifie que le code de statut est 200 OK
        self.assertIn('message', response.data)  # Vérifie que la réponse contient un message
    
    def test_send_verification_email_without_access_token(self):
        response = self.client.post(self.send_verification_email_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)  # Vérifie que le code de statut est 401 Unauthorized
    
    def test_resend_verification_email(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.get_access_token()}')  # Ajoute le jeton d'accès à l'en-tête
        response = self.client.post(self.send_verification_email_url)  # Envoie une requête POST à l'URL d'envoi du code de validation
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # Vérifie que le code de statut est 200 OK
        self.assertIn('message', response.data)  # Vérifie que la réponse contient un message

    # Test pour vérifier le code de validation de l'e-mail
    def test_verify_email(self):
        self.user.email_verification_code = uuid.uuid4()  # Définit un code de validation valide
        self.user.save()  # Enregistre les modifications dans la base de données
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.get_access_token()}')  # Ajoute le jeton d'accès à l'en-tête
        data = {
            'verification_code': str(self.user.email_verification_code)  # Utilise le code de validation de l'utilisateur
        }
        response = self.client.post(self.verify_email_url, data, format='json')  # Envoie une requête POST à l'URL de vérification
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # Vérifie que le code de statut est 200 OK
        self.assertIn('message', response.data)  # Vérifie que la réponse contient un message
        self.user.refresh_from_db()  # Actualise les données de l'utilisateur depuis la base de données
        self.assertTrue(self.user.email_verified)  # Vérifie que l'utilisateur est marqué comme vérifié

    # Méthode pour obtenir le jeton d'accès de l'utilisateur
    def get_access_token(self):
        refresh = RefreshToken.for_user(self.user)  # Génère un nouveau jeton d'actualisation pour l'utilisateur
        return str(refresh.access_token)  # Retourne le jeton d'accès

# Classe de tests pour la vue de déconnexion
class LogoutViewTests(APITestCase):

    def setUp(self):
        # Création d'un utilisateur pour les tests
        self.user = User.objects.create_user(
            username='testuser',
            email='testuser@example.com',
            password='testpassword'
        )
        # Génération de tokens JWT pour l'utilisateur
        self.refresh = RefreshToken.for_user(self.user)
        self.access_token = str(self.refresh.access_token)

        # URL pour la déconnexion
        self.logout_url = '/api/auth/logout/'

    def test_logout_with_valid_refresh_token(self):
        # Envoie une requête POST pour se déconnecter avec un token valide
        data = {'refresh': str(self.refresh)}
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')  # Ajoute le token d'accès
        response = self.client.post(self.logout_url, data, format='json')

        # Vérifie que la réponse retourne un statut 200
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_logout_with_invalid_refresh_token(self):
        # Envoie une requête POST avec un token d'actualisation invalide
        data = {'refresh': 'invalid_token'}
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')  # Ajoute le token d'accès
        response = self.client.post(self.logout_url, data, format='json')

        # Vérifie que la réponse retourne un statut 400
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)  # Vérifie que la réponse contient une clé "error"

    def test_logout_without_refresh_token(self):
        # Envoie une requête POST sans token d'actualisation
        data = {}
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.access_token}')  # Ajoute le token d'accès
        response = self.client.post(self.logout_url, data, format='json')

        # Vérifie que la réponse retourne un statut 400
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)  # Vérifie que la réponse contient une clé "error"

    def test_logout_without_access_token(self):
        # Envoie une requête POST sans access token dans l'en-tête
        data = {'refresh': str(self.refresh)}
        response = self.client.post(self.logout_url, data, format='json')

        # Vérifie que la réponse retourne un statut 401
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

# Classe de tests pour les vues de détails de l'utilisateur
class UserProfileTests(APITestCase):

    def setUp(self):
        # Création d'un utilisateur pour les tests
        self.user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpassword') # Crée un utilisateur
        self.login_url = reverse('login') # Génère l'URL pour la connexion
        self.user_details_url = reverse('get_user_details') # Génère l'URL pour obtenir les détails de l'utilisateur
        self.update_user_details_url = reverse('update_user_details') # Génère l'URL pour mettre à jour les détails de l'utilisateur

    def test_get_user_details(self):
        # Envoie une requête GET pour obtenir les détails de l'utilisateur
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.get_access_token()}')
        response = self.client.get(self.user_details_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['username'], 'testuser')
        self.assertEqual(response.data['email'], 'testuser@example.com')
    
    def test_update_user_details(self):
        # Envoie une requête PUT pour mettre à jour les détails de l'utilisateur
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.get_access_token()}')
        data = {'username': 'newuser', 'email': 'newemail@example.com'}
        response = self.client.put(self.update_user_details_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, 'newuser')
        self.assertEqual(self.user.email, 'newemail@example.com')
    
    def get_access_token(self):
        # Génère un jeton d'accès pour l'utilisateur
        data = {
            'username': 'testuser',
            'password': 'testpassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        return response.data['access']
    
class PasswordResetTests(APITestCase):

    def setUp(self):
        # Création d'un utilisateur pour les tests
        self.user = User.objects.create_user(username='testuser', email='testuser@example.com', password='testpassword')
        self.password_reset_request_url = reverse('password_reset_request')
        self.password_reset_confirm_url = reverse('password_reset_confirm', kwargs={'uidb64': urlsafe_base64_encode(force_bytes(self.user.pk)), 'token': PasswordResetTokenGenerator().make_token(self.user)})
    
    def test_password_reset_request(self):
        # Envoyer une demande de réinitialisation du mot de passe
        data = {'email': 'testuser@example.com'}
        response = self.client.post(self.password_reset_request_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data) # Vérifie que la réponse contient un message

    def test_password_reset_confirm(self):
        # Confimer la réinitialisation du mot de passe
        data = {'password': 'newpassword'}
        response = self.client.post(self.password_reset_confirm_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword'))
