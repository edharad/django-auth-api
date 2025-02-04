"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin # Importe le module admin de Django
from django.urls import path, include # Importe les fonctions path et include pour définir les URL

urlpatterns = [
    path('admin/', admin.site.urls), # URL pour l'interface d'administration
    path('api/auth/', include('authentication.urls')), # Inclut les URL de l'application d'authentification
]
