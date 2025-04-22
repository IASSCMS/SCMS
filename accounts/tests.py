from django.test import TestCase, Client
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.utils import timezone
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
import json
from datetime import timedelta

from .models import User, Token, PasswordResetToken

class AccountsAPITests(TestCase):
    def setUp(self):
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword123',
            first_name='Test',
            last_name='User'
        )
        
        # Create another user for testing duplicate checks
        self.user2 = User.objects.create_user(
            username='testuser2',
            email='test2@example.com',
            password='testpassword123'
        )
        
        # Set up API client
        self.client = APIClient()
        
        # URLs
        self.login_url = reverse('accounts:login')
        self.logout_url = reverse('accounts:logout')
        self.register_url = reverse('accounts:register')
        self.profile_url = reverse('accounts:profile')
        self.password_change_url = reverse('accounts:password_change')
        self.password_reset_url = reverse('accounts:password_reset')
        
        # Create a token for the user for testing authenticated endpoints
        self.token = Token.objects.create(
            user=self.user,
            key='test-token-key-123456789',
            expires=timezone.now() + timedelta(days=7)
        )

    def test_login_success(self):
        """Test successful login and token generation"""
        data = {
            'username': 'testuser',
            'password': 'testpassword123'
        }
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIn('token', response.data)
        self.assertEqual(response.data['user']['username'], 'testuser')
        self.assertEqual(response.data['user']['email'], 'test@example.com')

    def test_login_inactive_user(self):
        """Test login with inactive user"""
        self.user.is_active = False
        self.user.save()
        
        data = {
            'username': 'testuser',
            'password': 'testpassword123'
        }
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data['success'])
        self.assertIn('inactive', response.data['message'])

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        data = {
            'username': 'testuser',
            'password': 'wrongpassword'
        }
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Invalid credentials')

    def test_login_missing_fields(self):
        """Test login with missing fields"""
        data = {'username': 'testuser'}
        response = self.client.post(
            self.login_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    def test_logout(self):
        """Test logout and token deletion"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.post(self.logout_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        
        # Verify token is deleted
        with self.assertRaises(Token.DoesNotExist):
            Token.objects.get(key=self.token.key)

    def test_register_success(self):
        """Test successful user registration"""
        data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'newpassword123',
            'first_name': 'New',
            'last_name': 'User'
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertIn('token', response.data)
        self.assertEqual(response.data['user']['username'], 'newuser')
        self.assertEqual(response.data['user']['email'], 'new@example.com')
        
        # Verify user was created in database
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_register_duplicate_username(self):
        """Test registration with existing username"""
        data = {
            'username': 'testuser',  # already exists
            'email': 'new@example.com',
            'password': 'newpassword123'
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Username already exists')

    def test_register_duplicate_email(self):
        """Test registration with existing email"""
        data = {
            'username': 'newuser',
            'email': 'test@example.com',  # already exists
            'password': 'newpassword123'
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])
        self.assertEqual(response.data['message'], 'Email already exists')

    def test_register_missing_fields(self):
        """Test registration with missing required fields"""
        data = {
            'username': 'newuser',
            'email': 'new@example.com'
            # Missing password
        }
        response = self.client.post(
            self.register_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    def test_profile_get(self):
        """Test getting user profile information"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['user']['username'], 'testuser')
        self.assertEqual(response.data['user']['email'], 'test@example.com')
        self.assertEqual(response.data['user']['first_name'], 'Test')
        self.assertEqual(response.data['user']['last_name'], 'User')

    def test_profile_update(self):
        """Test updating user profile information"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        data = {
            'email': 'updated@example.com',
            'first_name': 'Updated',
            'last_name': 'Name'
        }
        response = self.client.post(
            self.profile_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['user']['email'], 'updated@example.com')
        self.assertEqual(response.data['user']['first_name'], 'Updated')
        self.assertEqual(response.data['user']['last_name'], 'Name')
        
        # Verify changes in the database
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, 'updated@example.com')
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.last_name, 'Name')

    def test_profile_unauthorized(self):
        """Test profile access without authentication"""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_password_change_success(self):
        """Test successful password change"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        data = {
            'old_password': 'testpassword123',
            'new_password': 'newpassword456'
        }
        response = self.client.post(
            self.password_change_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        
        # Verify password was changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword456'))

    def test_password_change_wrong_old_password(self):
        """Test password change with incorrect old password"""
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {self.token.key}')
        data = {
            'old_password': 'wrongpassword',
            'new_password': 'newpassword456'
        }
        response = self.client.post(
            self.password_change_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertFalse(response.data['success'])

    def test_password_reset_request(self):
        """Test password reset request"""
        data = {'email': 'test@example.com'}
        response = self.client.post(
            self.password_reset_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        
        # Verify a reset token was created
        self.assertTrue(PasswordResetToken.objects.filter(user=self.user).exists())

    def test_password_reset_nonexistent_email(self):
        """Test password reset with non-existent email"""
        data = {'email': 'nonexistent@example.com'}
        response = self.client.post(
            self.password_reset_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        # Should still return 200 for security reasons
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])

    def test_password_reset_confirm(self):
        """Test password reset confirmation"""
        # Create a reset token
        reset_token = PasswordResetToken.objects.create(
            user=self.user,
            token='test-reset-token-123456789'
        )
        
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        confirm_url = reverse('accounts:password_reset_confirm', 
                             kwargs={'uidb64': uidb64, 'token': reset_token.token})
        
        data = {'new_password': 'resetpassword789'}
        response = self.client.post(
            confirm_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['success'])
        
        # Verify password was changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('resetpassword789'))
        
        # Verify token was deleted
        with self.assertRaises(PasswordResetToken.DoesNotExist):
            PasswordResetToken.objects.get(pk=reset_token.pk)

    def test_password_reset_confirm_invalid_token(self):
        """Test password reset with invalid token"""
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        confirm_url = reverse('accounts:password_reset_confirm', 
                             kwargs={'uidb64': uidb64, 'token': 'invalid-token'})
        
        data = {'new_password': 'resetpassword789'}
        response = self.client.post(
            confirm_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertFalse(response.data['success'])

    def test_token_expiration(self):
        """Test that expired tokens are considered invalid"""
        # Create an expired token
        expired_token = Token.objects.create(
            user=self.user2,
            key='expired-token-123456789',
            expires=timezone.now() - timedelta(days=1)  # 1 day in the past
        )
        
        # Attempt to use expired token
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {expired_token.key}')
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)