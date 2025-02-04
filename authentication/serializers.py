from rest_framework import serializers # Importer le module serializers de Django REST Framework
from .models import User # Importer le modèle User défini dans .../authentication/models.py
from .service import create_user, send_verification_email

# Serializer pour le modèle User
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User #Specifie le modèle à sérialiser
        fields = ['id', 'username', 'email', 'is_verified'] # Champs à inclure dans la sérialisation
        read_only_fields = ['is_verified'] # Champs en lecture seule

# Serializer pour l'inscription d'un utilisateur
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=8, write_only=True) # Champ de mot de passe en écriture seule

    class Meta:
        model = User # Specifie le modèle à sérialiser
        fields = ['email', 'username', 'password'] # Champs à inclure dans la sérialisation

    # Methode pour créer un utilisateur
    def create(self, validated_data):
        user = create_user(validated_data)
        send_verification_email(user)
        return user

