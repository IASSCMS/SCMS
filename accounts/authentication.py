from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings
import jwt
from .models import User

class JWTAuthentication(BaseAuthentication):
    """
    JWT Authentication for Django REST Framework.
    
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prefixed with the string "Bearer ".  For example:
        Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    """
    keyword = 'Bearer'
    
    def authenticate(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth or not auth.startswith(self.keyword + ' '):
            return None
        
        token = auth.split(' ')[1]
        return self.authenticate_credentials(token)
    
    def authenticate_credentials(self, token):
        try:
            # Decode JWT token
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=['HS256']
            )
            
            # Get user from payload
            user_id = payload.get('user_id')
            user = User.objects.get(id=user_id)
            
            if not user.is_active:
                raise AuthenticationFailed('User inactive or deleted')
                
            return (user, token)
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')
    
    def authenticate_header(self, request):
        return self.keyword