from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('edit_profile/', views.edit_profile, name='edit_profile'),
    path('change_password/', views.change_password, name='change_password'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('reset_password_confirm/<uidb64>/<token>/', views.reset_password_confirm, name='reset_password_confirm'),
    path('reset_password_complete/', views.reset_password_complete, name='reset_password_complete'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('activate_complete/', views.activate_complete, name='activate_complete'),
    path('activate_email/', views.activate_email, name='activate_email'),
    path('activate_email_complete/', views.activate_email_complete, name='activate_email_complete'),
]