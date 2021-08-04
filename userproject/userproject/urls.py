"""userproject URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
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
from django.contrib import admin
from django.urls import path
from userapp.views import login, userdata,register,changepassword,activate,deluser,logout,resetpassword,activate1,account_activate

urlpatterns = [
    path('admin/', admin.site.urls),
    path("userdata/<int:pk>",userdata),
    path("userdata/",userdata),
    path("register",register),
    path('activate/<slug:uidb64>/<slug:token>/', activate, name='activate'),
    path('activate1/<slug:uidb64>/<slug:token>/', activate1, name='activate1'),
    path('deluser/<str:username>', deluser),
    path("login",login),
    path("logout",logout),
    path("changepassword",changepassword),
    path('resetpassword', resetpassword),
    path('account_activate', account_activate),
]