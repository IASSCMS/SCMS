from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('auth/login/', views.login_view, name='login'),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/register/', views.register_view, name='register'),
    path('auth/profile/', views.profile_view, name='profile'),
    path('auth/password/change/', views.password_change_view, name='password_change'),
    path('auth/password/reset/', views.password_reset_view, name='password_reset'),
    path('auth/password/reset-confirm/<uidb64>/<token>/', views.password_reset_confirm_view, name='password_reset_confirm'),
]