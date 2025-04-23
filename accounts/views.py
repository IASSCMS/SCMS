from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
import json
import uuid
from django.utils import timezone
from datetime import timedelta
import secrets
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
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

@api_view(['POST'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def register_view(request):
    data = request.data
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')
    first_name = data.get('first_name', '')
    last_name = data.get('last_name', '')
    role_id = data.get('role_id', 2)  # Default to regular user role

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
    
    # Set role_id (assuming you have a role field or related model)
    user.role_id = role_id
    user.save()
    
    return Response({
        'success': True,
        'message': 'User registered successfully',
        'user_id': user.id
    })

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    data = request.data
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')

    if (not username and not email) or not password:
        return Response({
            'success': False,
            'message': 'Please provide email/username and password'
        }, status=400)
    
    # Try to authenticate with username or email
    user = None
    if username:
        user = authenticate(request, username=username, password=password)
    elif email:
        try:
            user_obj = User.objects.get(email=email)
            user = authenticate(request, username=user_obj.username, password=password)
        except User.DoesNotExist:
            pass
    
    # Check if user is active
    if user and not user.is_active:
        return Response({
            'success': False, 
            'message': 'Account is inactive'
        }, status=401)
    
    if user is not None:
        login(request, user)
        
        # Generate token
        token = generate_token(user)
        
        return Response({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': {
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'role_id': getattr(user, 'role_id', 2),  # Default to regular user if no role_id
            }
        })
    else:
        return Response({
            'success': False,
            'message': 'Invalid credentials'
        }, status=401)

@csrf_exempt
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

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_profile_view(request):
    user = request.user
    
    return Response({
        'success': True,
        'user': {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'role_id': getattr(user, 'role_id', 2),
            'is_verified': True  # Add appropriate field from model
        }
    })

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_profile_view(request):
    user = request.user
    data = request.data
    
    # Update user fields if provided
    if 'username' in data:
        # Check if username is already taken by another user
        if User.objects.exclude(id=user.id).filter(username=data['username']).exists():
            return Response({
                'success': False,
                'message': 'Username already exists'
            }, status=400)
        user.username = data['username']
        
    if 'email' in data:
        # Check if email is already taken by another user
        if User.objects.exclude(id=user.id).filter(email=data['email']).exists():
            return Response({
                'success': False,
                'message': 'Email already exists'
            }, status=400)
        user.email = data['email']
        
    if 'first_name' in data:
        user.first_name = data['first_name']
        
    if 'last_name' in data:
        user.last_name = data['last_name']
    
    user.save()
    
    return Response({
        'success': True,
        'message': 'Profile updated successfully'
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def password_change_view(request):
    data = request.data
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

@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_view(request):
    data = request.data
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
        
        # Create email message
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

@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_confirm_view(request, uidb64, token):
    """Handle the password reset confirmation"""
    try:
        # Decode the user id
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
        data = request.data
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

# Admin specific views
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_get_all_users(request):
    """Admin endpoint to get all users"""
    user = request.user
    
    # Check if user is admin (role_id = 1)
    if getattr(user, 'role_id', 0) != 1:
        return Response({
            'success': False,
            'message': 'Permission denied'
        }, status=403)
    
    # Get query parameters for pagination
    page = int(request.GET.get('page', 1))
    limit = int(request.GET.get('limit', 10))
    role_id = request.GET.get('role_id')
    
    # Calculate offset
    offset = (page - 1) * limit
    
    # Query all users
    users_query = User.objects.all()
    
    # Filter by role_id if provided
    if role_id:
        users_query = users_query.filter(role_id=role_id)
    
    # Get total count for pagination
    total_count = users_query.count()
    
    # Get paginated users
    users = users_query[offset:offset+limit]
    
    # Format user data
    user_list = []
    for user in users:
        user_list.append({
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'role_id': getattr(user, 'role_id', 2),
            'is_verified': getattr(user, 'is_verified', False)
        })
    
    return Response({
        'success': True,
        'users': user_list,
        'pagination': {
            'total': total_count,
            'page': page,
            'limit': limit,
            'pages': (total_count + limit - 1) // limit  # Ceiling division
        }
    })

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def admin_update_user(request, user_id):
    """Admin endpoint to update user"""
    admin = request.user
    
    # Check if user is admin (role_id = 1)
    if getattr(admin, 'role_id', 0) != 1:
        return Response({
            'success': False,
            'message': 'Permission denied'
        }, status=403)
    
    try:
        user = User.objects.get(pk=user_id)
        data = request.data
        
        # Update fields if provided
        if 'email' in data:
            user.email = data['email']
        if 'role_id' in data:
            user.role_id = data['role_id']
        if 'is_verified' in data:
            user.is_verified = data['is_verified']
        
        user.save()
        
        return Response({
            'success': True,
            'message': 'User updated successfully'
        })
    except User.DoesNotExist:
        return Response({
            'success': False,
            'message': 'User not found'
        }, status=404)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def admin_delete_user(request, user_id):
    """Admin endpoint to delete user"""
    admin = request.user
    
    # Check if user is admin (role_id = 1)
    if getattr(admin, 'role_id', 0) != 1:
        return Response({
            'success': False,
            'message': 'Permission denied'
        }, status=403)
    
    try:
        user = User.objects.get(pk=user_id)
        
        # Prevent admin from deleting themselves
        if user.id == admin.id:
            return Response({
                'success': False,
                'message': 'Cannot delete your own account'
            }, status=400)
        
        user.delete()
        
        return Response({
            'success': True,
            'message': 'User deleted successfully'
        })
    except User.DoesNotExist:
        return Response({
            'success': False,
            'message': 'User not found'
        }, status=404)