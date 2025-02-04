from django.core.mail import send_mail
from .models import User

def create_user(validated_data):
    """Crée un utilisateur et retourne l'instance"""
    user = User.objects.create_user(
        username=validated_data['username'],
        email=validated_data['email'],
        password=validated_data['password']
    )
    return user

def send_verification_email(user):
    """Envoie un email de vérification"""
    send_mail(
        subject="Vérification de votre email",
        message="Cliquez sur ce lien pour vérifier votre email.",
        from_email="no-reply@monapp.com",
        recipient_list=[user.email]
    )

