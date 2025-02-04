from django.urls import path, include
from .views.auth import RegisterView, LoginView, LogoutView
from .views.email import SendVerificationCodeView, ResendVerificationCodeView, VerifyEmailView
from .views.password import PasswordResetRequestView, PasswordResetConfirmView
from .views.onfido import CreateOnfidoCheckView, GetOnfidoCheckStatusView
from .views.user import GetUserDetailsView, UpdateUserDetailsView, DeleteUserView

urlpatterns = [
    # 🔹 Authentification
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # 🔹 Vérification d'email
    path("email/send-verification-code/", SendVerificationCodeView.as_view(), name="send_verification_code"),
    path("email/resend-verification-code/", ResendVerificationCodeView.as_view(), name="resend_verification_code"),
    path("email/verify/", VerifyEmailView.as_view(), name="verify_email"),

    # 🔹 Réinitialisation de mot de passe
    path("password/reset-request/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    path("password/reset-confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),

    # 🔹 Vérification Onfido
    path("onfido/create-check/", CreateOnfidoCheckView.as_view(), name="create_onfido_check"),
    path("onfido/check-status/", GetOnfidoCheckStatusView.as_view(), name="get_onfido_check_status"),

    # 🔹 Gestion du profil utilisateur
    path("user/details/", GetUserDetailsView.as_view(), name="get_user_details"),
    path("user/update/", UpdateUserDetailsView.as_view(), name="update_user_details"),
    path("user/delete/", DeleteUserView.as_view(), name="delete_user"),
]
