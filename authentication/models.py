from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid # Importe le module uuid pour générer des codes uniques

class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    email_verification_code = models.UUIDField(default=uuid.uuid4, editable=False)
    # Ajoutez d'autres champs nécessaires ici

    def __str__(self):
        return self.username

