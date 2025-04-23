from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Token
from django.utils import timezone

class TokenAuthentication(BaseAuthentication):
    """
    Custom token-based authentication for Django REST Framework.
    
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prefixed with the string "Token ".  For example:
        Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
    """
    keyword = 'Token'
    
    def authenticate(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth or not auth.startswith(self.keyword + ' '):
            return None
        
        token_key = auth.split(' ')[1]
        return self.authenticate_credentials(token_key)
    
    def authenticate_credentials(self, key):
        try:
            token = Token.objects.get(key=key)
        except Token.DoesNotExist:
            raise AuthenticationFailed('Invalid token')
        
        if token.expires < timezone.now():
            token.delete()
            raise AuthenticationFailed('Token has expired')
        
        if not token.user.is_active:
            raise AuthenticationFailed('User inactive or deleted')
        
        return (token.user, token)
    
    def authenticate_header(self, request):
        return self.keyword


class BearerTokenAuthentication(BaseAuthentication):
    """
    JWT/Bearer token-based authentication for Django REST Framework.
    
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prefixed with the string "Bearer ".  For example:
        Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    """
    keyword = 'Bearer'
    
    def authenticate(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth or not auth.startswith(self.keyword + ' '):
            return None
        
        token_key = auth.split(' ')[1]
        return self.authenticate_credentials(token_key)
    
    def authenticate_credentials(self, key):
        # We'll use our Token model for Bearer tokens as well
        try:
            token = Token.objects.get(key=key)
        except Token.DoesNotExist:
            raise AuthenticationFailed('Invalid token')
        
        if token.expires < timezone.now():
            token.delete()
            raise AuthenticationFailed('Token has expired')
        
        if not token.user.is_active:
            raise AuthenticationFailed('User inactive or deleted')
        
        return (token.user, token)
    
    def authenticate_header(self, request):
        return self.keyword