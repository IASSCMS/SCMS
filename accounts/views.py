from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST
import json
import uuid
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth.hashers import make_password, check_password

from .models import User, Token, PasswordResetToken

# Token generation function
def generate_token(user):
    # Delete any existing tokens for this user
    Token.objects.filter(user=user).delete()
    
    # Generate a new token
    token_key = uuid.uuid4().hex
    expires = timezone.now() + timedelta(days=7)  # Token valid for 7 days
    
    # Create and save the new token
    token = Token.objects.create(user=user, key=token_key, expires=expires)
    return token.key

# Token authentication middleware
def get_user_from_token(token_key):
    try:
        token = Token.objects.get(key=token_key)
        if token.is_valid():
            return token.user
        return None
    except Token.DoesNotExist:
        return None

@require_POST
@ensure_csrf_cookie
def login_view(request):
    data = json.loads(request.body)
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return JsonResponse({
            'success': False,
            'message': 'Please provide both username and password'
        }, status=400)
    
    # Use Django's authenticate function
    user = authenticate(request, username=username, password=password)
    
    if user is not None:
        if user.is_active:
            login(request, user)
            
            # Generate token
            token = generate_token(user)
            
            return JsonResponse({
                'success': True,
                'message': 'Login successful',
                'token': token,
                'user': {
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                }
            })
        else:
            return JsonResponse({
                'success': False, 
                'message': 'Account is inactive'
            }, status=401)
    else:
        return JsonResponse({
            'success': False,
            'message': 'Invalid credentials'
        }, status=401)


def logout_view(request):
    # Get the token from the request
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        # Delete the token
        Token.objects.filter(key=token_key).delete()
    
    logout(request)
    return JsonResponse({
        'success': True,
        'message': 'Logged out successfully'
    })


@require_POST
@ensure_csrf_cookie
def register_view(request):
    data = json.loads(request.body)
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    first_name = data.get('first_name', '')
    last_name = data.get('last_name', '')

    if not username or not email or not password:
        return JsonResponse({
            'success': False,
            'message': 'Please provide username, email and password'
        }, status=400)

    # Check if username already exists
    if User.objects.filter(username=username).exists():
        return JsonResponse({
            'success': False,
            'message': 'Username already exists'
        }, status=400)

    # Check if email already exists
    if User.objects.filter(email=email).exists():
        return JsonResponse({
            'success': False,
            'message': 'Email already exists'
        }, status=400)
    
    # Create new user using Django's User model create_user method
    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,  # create_user handles password hashing
        first_name=first_name,
        last_name=last_name
    )
    
    # Log the user in after registration
    login(request, user)
    
    # Generate token
    token = generate_token(user)
    
    return JsonResponse({
        'success': True,
        'message': 'Registration successful',
        'token': token,
        'user': {
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        }
    })


def token_required(view_func):
    """Decorator to check for valid token authentication"""
    def wrapped_view(request, *args, **kwargs):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Token '):
            return JsonResponse({
                'success': False,
                'message': 'Authentication required'
            }, status=401)
        
        token_key = auth_header.split(' ')[1]
        user = get_user_from_token(token_key)
        
        if not user:
            return JsonResponse({
                'success': False,
                'message': 'Invalid or expired token'
            }, status=401)
        
        request.user = user
        return view_func(request, *args, **kwargs)
    
    return wrapped_view


@token_required
def profile_view(request):
    user = request.user
    
    if request.method == 'GET':
        return JsonResponse({
            'success': True,
            'user': {
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'date_joined': user.date_joined
            }
        })
    
    elif request.method == 'POST':
        data = json.loads(request.body)
        
        # Update user fields if provided
        if 'email' in data:
            user.email = data['email']
        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        
        user.save()
        
        return JsonResponse({
            'success': True,
            'message': 'Profile updated successfully',
            'user': {
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        })


@token_required
@require_POST
def password_change_view(request):
    data = json.loads(request.body)
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    
    if not old_password or not new_password:
        return JsonResponse({
            'success': False,
            'message': 'Please provide both old and new passwords'
        }, status=400)
    
    user = request.user
    
    # Use Django's check_password
    if not user.check_password(old_password):
        return JsonResponse({
            'success': False,
            'message': 'Incorrect old password'
        }, status=401)
    
    # Update password with Django's set_password
    user.set_password(new_password)
    user.save()
    
    return JsonResponse({
        'success': True,
        'message': 'Password changed successfully'
    })


import secrets
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

@require_POST
def password_reset_view(request):
    data = json.loads(request.body)
    email = data.get('email', '')
    
    if not email:
        return JsonResponse({
            'success': False,
            'message': 'Please provide email address'
        }, status=400)
    
    try:
        user = User.objects.get(email=email)
        
        # Generate a secure token
        token = secrets.token_urlsafe(32)
        
        # Save token in the database
        PasswordResetToken.objects.filter(user=user).delete()  # Remove old tokens
        reset_token = PasswordResetToken.objects.create(user=user, token=token)
        
        # Create reset URL
        reset_url = f"{settings.FRONTEND_URL}/reset-password/{urlsafe_base64_encode(force_bytes(user.pk))}/{token}/"
        
        # Send email
        subject = "Password Reset Request"
        message = render_to_string('password_reset_email.html', {
            'user': user,
            'reset_url': reset_url,
        })
        
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], html_message=message)
        
        return JsonResponse({
            'success': True,
            'message': 'Password reset instructions sent to your email'
        })
    except User.DoesNotExist:
        # For security reasons, don't reveal that the email doesn't exist
        return JsonResponse({
            'success': True,
            'message': 'Password reset instructions sent to your email if account exists'
        })


@require_POST
def password_reset_confirm_view(request, uidb64, token):
    """Handle the password reset confirmation"""
    try:
        # Decode the user id
        from django.utils.encoding import force_str
        from django.utils.http import urlsafe_base64_decode
        
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        
        # Verify token
        reset_token = PasswordResetToken.objects.get(user=user, token=token)
        if not reset_token.is_valid():
            return JsonResponse({
                'success': False,
                'message': 'Password reset link is invalid or has expired'
            }, status=400)
        
        # Get new password
        data = json.loads(request.body)
        new_password = data.get('new_password', '')
        
        if not new_password:
            return JsonResponse({
                'success': False,
                'message': 'Please provide a new password'
            }, status=400)
        
        # Update password
        user.set_password(new_password)
        user.save()
        
        # Delete the used token
        reset_token.delete()
        
        return JsonResponse({
            'success': True,
            'message': 'Password has been reset successfully'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': 'Password reset link is invalid or has expired'
        }, status=400)