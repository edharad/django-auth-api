# Django Authentication API

This project is a **Django REST API** for user authentication using **JWT (JSON Web Tokens)**.
It supports **user registration, login, password reset, and identity verification with Onfido**.

## ✨ Features

- User **registration & login** with JWT authentication
- Mail verification with code
- **Password reset** via email tokens
- Blacklist tokens (logout)
- **Identity verification** using Onfido SDK
- Django REST Framework (**DRF**) based API

## 📌 Installation

1. Clone the repository:

  ```bash
  git clone https://github.com/edharad/django-auth-api.git
  cd django-auth-api
  ```

2. Create a virtual environment and install dependencies:

  ```bash
  python -m venv venv
  source venv/bin/activate  # On Windows use: venv\\Scripts\\activate
  pip install -r requirements.txt
  ```

3. Apply migration and start the server

```bash
python manage.py migrate
python manage.py runserver
```

4. Create a super user

```bash
python manage.py createsuperuser
```

5. Launch server

```bash
python manage.py runserver
```

6. API will be available at <http://127.0.0.1:8000/api/auth/>

📖 API Endpoints

|Méthode  | Endpoint  | Description |
|---------|-----------|-------------|
|POST | /api/auth/register/ |Inscription
|POST | /api/auth/login/    |Connexion
|POST | /api/auth/logout/   |Déconnexion
|POST | /api/auth/email/send-verification-code/ |Envoi du code
|POST | /api/auth/email/verify/ | Vérification email
|POST | /api/auth/password/reset-request/ | Demande de reset
|POST | /api/auth/password/reset-confirm/<uid>/<token>/ | Reset du mot de passe

🛠 Configuration

SECRET_KEY=votre_clé_secrète
DEBUG=True
ALLOWED_HOSTS=*
EMAIL_BACKEND=django.core.mail.backends.console.EmailBackend
ONFIDO_API_KEY=votre_clé_onfido
FRONTEND_URL=http://localhost:3000

📝 License

This project is licensed under the MIT License.
