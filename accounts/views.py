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
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

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

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['username', 'password'],
        properties={
            'username': openapi.Schema(type=openapi.TYPE_STRING, description='Username'),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description='Password'),
        }
    ),
    responses={
        200: openapi.Response(
            description="Login successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'token': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'username': openapi.Schema(type=openapi.TYPE_STRING),
                            'email': openapi.Schema(type=openapi.TYPE_STRING),
                            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    )
                }
            )
        ),
        400: openapi.Response(
            description="Bad request",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        ),
        401: openapi.Response(
            description="Unauthorized",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def login_view(request):
    data = json.loads(request.body)
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return Response({
            'success': False,
            'message': 'Please provide both username and password'
        }, status=400)
    
    # Get the user first to check if active
    try:
        user = User.objects.get(username=username)
        if not user.is_active:
            return Response({
                'success': False, 
                'message': 'Account is inactive'  # This message needs to contain 'inactive'
            }, status=401)
    except User.DoesNotExist:
        pass
    
    # Use Django's authenticate function
    user = authenticate(request, username=username, password=password)
    
    if user is not None:
        login(request, user)
        
        # Generate token
        token = generate_token(user)
        
        return Response({
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
        return Response({
            'success': False,
            'message': 'Invalid credentials'
        }, status=401)


@swagger_auto_schema(
    method='post',
    responses={
        200: openapi.Response(
            description="Logout successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )
    },
    manual_parameters=[
        openapi.Parameter(
            name='Authorization',
            in_=openapi.IN_HEADER,
            description='Token {token}',
            type=openapi.TYPE_STRING,
            required=True
        )
    ]
)
@api_view(['POST'])
def logout_view(request):
    # Get the token from the request
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Token '):
        token_key = auth_header.split(' ')[1]
        # Delete the token
        Token.objects.filter(key=token_key).delete()
    
    logout(request)
    return Response({
        'success': True,
        'message': 'Logged out successfully'
    })


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['username', 'email', 'password'],
        properties={
            'username': openapi.Schema(type=openapi.TYPE_STRING),
            'email': openapi.Schema(type=openapi.TYPE_STRING, format='email'),
            'password': openapi.Schema(type=openapi.TYPE_STRING),
            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
        }
    ),
    responses={
        200: openapi.Response(
            description="Registration successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'token': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'username': openapi.Schema(type=openapi.TYPE_STRING),
                            'email': openapi.Schema(type=openapi.TYPE_STRING),
                            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    )
                }
            )
        ),
        400: openapi.Response(
            description="Bad request",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def register_view(request):
    data = json.loads(request.body)
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    first_name = data.get('first_name', '')
    last_name = data.get('last_name', '')

    if not username or not email or not password:
        return Response({
            'success': False,
            'message': 'Please provide username, email and password'
        }, status=400)

    # Check if username already exists
    if User.objects.filter(username=username).exists():
        return Response({
            'success': False,
            'message': 'Username already exists'
        }, status=400)

    # Check if email already exists
    if User.objects.filter(email=email).exists():
        return Response({
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
    
    return Response({
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


# Custom decorator for token authentication
def token_required(view_func):
    """Decorator to check for valid token authentication"""
    def wrapped_view(request, *args, **kwargs):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Token '):
            return Response({
                'success': False,
                'message': 'Authentication required'
            }, status=401)
        
        token_key = auth_header.split(' ')[1]
        user = get_user_from_token(token_key)
        
        if not user:
            return Response({
                'success': False,
                'message': 'Invalid or expired token'
            }, status=401)
        
        request.user = user
        return view_func(request, *args, **kwargs)
    
    return wrapped_view


@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(
            description="Profile data retrieved successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'user': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'username': openapi.Schema(type=openapi.TYPE_STRING),
                            'email': openapi.Schema(type=openapi.TYPE_STRING),
                            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                            'date_joined': openapi.Schema(type=openapi.TYPE_STRING, format='date-time'),
                        }
                    )
                }
            )
        ),
        401: openapi.Response(
            description="Unauthorized",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )
    },
    manual_parameters=[
        openapi.Parameter(
            name='Authorization',
            in_=openapi.IN_HEADER,
            description='Token {token}',
            type=openapi.TYPE_STRING,
            required=True
        )
    ]
)
@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, format='email'),
            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
        }
    ),
    responses={
        200: openapi.Response(
            description="Profile updated successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'username': openapi.Schema(type=openapi.TYPE_STRING),
                            'email': openapi.Schema(type=openapi.TYPE_STRING),
                            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
                            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    )
                }
            )
        ),
        401: openapi.Response(
            description="Unauthorized",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )
    },
    manual_parameters=[
        openapi.Parameter(
            name='Authorization',
            in_=openapi.IN_HEADER,
            description='Token {token}',
            type=openapi.TYPE_STRING,
            required=True
        )
    ]
)
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def profile_view(request):
    user = request.user
    
    if request.method == 'GET':
        return Response({
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
        
        return Response({
            'success': True,
            'message': 'Profile updated successfully',
            'user': {
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        })


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['old_password', 'new_password'],
        properties={
            'old_password': openapi.Schema(type=openapi.TYPE_STRING),
            'new_password': openapi.Schema(type=openapi.TYPE_STRING),
        }
    ),
    responses={
        200: openapi.Response(
            description="Password changed successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        ),
        400: openapi.Response(
            description="Bad request",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        ),
        401: openapi.Response(
            description="Unauthorized",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )
    },
    manual_parameters=[
        openapi.Parameter(
            name='Authorization',
            in_=openapi.IN_HEADER,
            description='Token {token}',
            type=openapi.TYPE_STRING,
            required=True
        )
    ]
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def password_change_view(request):
    data = json.loads(request.body)
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    
    if not old_password or not new_password:
        return Response({
            'success': False,
            'message': 'Please provide both old and new passwords'
        }, status=400)
    
    user = request.user
    
    # Use Django's check_password
    if not user.check_password(old_password):
        return Response({
            'success': False,
            'message': 'Incorrect old password'
        }, status=401)
    
    # Update password with Django's set_password
    user.set_password(new_password)
    user.save()
    
    return Response({
        'success': True,
        'message': 'Password changed successfully'
    })


import secrets
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['email'],
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, format='email'),
        }
    ),
    responses={
        200: openapi.Response(
            description="Password reset email sent",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        ),
        400: openapi.Response(
            description="Bad request",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_view(request):
    data = json.loads(request.body)
    email = data.get('email', '')
    
    if not email:
        return Response({
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
        
        # Create reset URL - Use getattr to provide a default value if FRONTEND_URL is not set
        frontend_url = getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')
        reset_url = f"{frontend_url}/reset-password/{urlsafe_base64_encode(force_bytes(user.pk))}/{token}/"
        
        # Create a simple text-based email message
        subject = "Password Reset Request"
        message = f"""Hello {user.username},

You requested a password reset for your account. Please click the link below to reset your password:

{reset_url}

If you didn't request this reset, you can safely ignore this email.

Thank you,
The Support Team"""
        
        # Default from email with fallback
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com')
        
        # Send email
        send_mail(subject, message, from_email, [user.email])
        
        return Response({
            'success': True,
            'message': 'Password reset instructions sent to your email'
        })
    except User.DoesNotExist:
        # For security reasons, don't reveal that the email doesn't exist
        return Response({
            'success': True,
            'message': 'Password reset instructions sent to your email if account exists'
        })


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        required=['new_password'],
        properties={
            'new_password': openapi.Schema(type=openapi.TYPE_STRING),
        }
    ),
    responses={
        200: openapi.Response(
            description="Password reset successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        ),
        400: openapi.Response(
            description="Bad request",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
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
            return Response({
                'success': False,
                'message': 'Password reset link is invalid or has expired'
            }, status=400)
        
        # Get new password
        data = json.loads(request.body)
        new_password = data.get('new_password', '')
        
        if not new_password:
            return Response({
                'success': False,
                'message': 'Please provide a new password'
            }, status=400)
        
        # Update password
        user.set_password(new_password)
        user.save()
        
        # Delete the used token
        reset_token.delete()
        
        return Response({
            'success': True,
            'message': 'Password has been reset successfully'
        })
    except Exception as e:
        return Response({
            'success': False,
            'message': 'Password reset link is invalid or has expired'
        }, status=400)