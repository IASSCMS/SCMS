from django.test import TestCase, Client
from django.urls import reverse
import json
from .models import User, Token, PasswordResetToken
from django.utils import timezone
from datetime import timedelta
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

class AuthenticationTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.profile_url = reverse('profile')
        self.password_change_url = reverse('password_change')
        self.password_reset_url = reverse('password_reset')
        
        # Create a test user for reuse
        self.test_user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='securepassword',
            first_name='Test',
            last_name='User'
        )
        
        # Create a token for the test user
        self.test_token = Token.objects.create(
            user=self.test_user,
            key='testtoken123',
            expires=timezone.now() + timedelta(days=7)
        )
        
    def test_user_registration(self):
        """Test user registration endpoint"""
        response = self.client.post(
            self.register_url,
            data=json.dumps({
                'username': 'newuser',
                'email': 'new@example.com',
                'password': 'securepassword',
                'first_name': 'New',
                'last_name': 'User'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        self.assertIn('token', response.json())
        
        # Verify user was created in the database
        self.assertTrue(User.objects.filter(username='newuser').exists())
    
    def test_registration_duplicate_username(self):
        """Test registration with existing username"""
        response = self.client.post(
            self.register_url,
            data=json.dumps({
                'username': 'testuser',  # Already exists
                'email': 'another@example.com',
                'password': 'securepassword'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()['success'])
        self.assertIn('Username already exists', response.json()['message'])
    
    def test_registration_duplicate_email(self):
        """Test registration with existing email"""
        response = self.client.post(
            self.register_url,
            data=json.dumps({
                'username': 'anotheruser',
                'email': 'test@example.com',  # Already exists
                'password': 'securepassword'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()['success'])
        self.assertIn('Email already exists', response.json()['message'])
    
    def test_registration_missing_fields(self):
        """Test registration with missing required fields"""
        response = self.client.post(
            self.register_url,
            data=json.dumps({
                'username': 'newuser',
                # Missing email and password
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()['success'])
        
    def test_user_login(self):
        """Test user login with correct credentials"""
        response = self.client.post(
            self.login_url,
            data=json.dumps({
                'username': 'testuser',
                'password': 'securepassword'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        self.assertIn('token', response.json())
        self.assertEqual(response.json()['user']['username'], 'testuser')
        
    def test_login_invalid_credentials(self):
        """Test login with wrong password"""
        response = self.client.post(
            self.login_url,
            data=json.dumps({
                'username': 'testuser',
                'password': 'wrongpassword'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()['success'])
        
    def test_login_inactive_user(self):
        """Test login with inactive user"""
        # Make the test user inactive
        self.test_user.is_active = False
        self.test_user.save()
        
        response = self.client.post(
            self.login_url,
            data=json.dumps({
                'username': 'testuser',
                'password': 'securepassword'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()['success'])
        self.assertIn('inactive', response.json()['message'].lower())
        
        # Restore active status for other tests
        self.test_user.is_active = True
        self.test_user.save()
        
    def test_logout(self):
        """Test user logout"""
        response = self.client.post(
            self.logout_url,
            HTTP_AUTHORIZATION=f'Token {self.test_token.key}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        
        # Verify token was deleted
        self.assertFalse(Token.objects.filter(key=self.test_token.key).exists())
        
    def test_profile_get(self):
        """Test getting user profile"""
        response = self.client.get(
            self.profile_url,
            HTTP_AUTHORIZATION=f'Token {self.test_token.key}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        self.assertEqual(response.json()['user']['username'], 'testuser')
        self.assertEqual(response.json()['user']['email'], 'test@example.com')
        
    def test_profile_update(self):
        """Test updating user profile"""
        response = self.client.post(
            self.profile_url,
            data=json.dumps({
                'first_name': 'Updated',
                'last_name': 'Name'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.test_token.key}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        
        # Verify user was updated in the database
        user = User.objects.get(username='testuser')
        self.assertEqual(user.first_name, 'Updated')
        self.assertEqual(user.last_name, 'Name')
        
    def test_profile_no_auth(self):
        """Test accessing profile without authentication"""
        response = self.client.get(self.profile_url)
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()['success'])
        
    def test_password_change(self):
        """Test changing password"""
        response = self.client.post(
            self.password_change_url,
            data=json.dumps({
                'old_password': 'securepassword',
                'new_password': 'newpassword123'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.test_token.key}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        
        # Verify password was changed
        user = User.objects.get(username='testuser')
        self.assertTrue(user.check_password('newpassword123'))
        
    def test_password_change_wrong_old_password(self):
        """Test changing password with incorrect old password"""
        response = self.client.post(
            self.password_change_url,
            data=json.dumps({
                'old_password': 'wrongpassword',
                'new_password': 'newpassword123'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Token {self.test_token.key}'
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()['success'])
        
    def test_password_change_no_auth(self):
        """Test changing password without authentication"""
        response = self.client.post(
            self.password_change_url,
            data=json.dumps({
                'old_password': 'securepassword',
                'new_password': 'newpassword123'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()['success'])
        
    def test_password_reset_request(self):
        """Test requesting password reset"""
        response = self.client.post(
            self.password_reset_url,
            data=json.dumps({
                'email': 'test@example.com'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        
        # Verify token was created
        self.assertTrue(PasswordResetToken.objects.filter(user=self.test_user).exists())
        
    def test_password_reset_nonexistent_email(self):
        """Test requesting password reset for nonexistent email"""
        response = self.client.post(
            self.password_reset_url,
            data=json.dumps({
                'email': 'nonexistent@example.com'
            }),
            content_type='application/json'
        )
        # Should still return 200 for security reasons
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        
    def test_password_reset_confirm(self):
        """Test confirming password reset"""
        # Create a reset token
        token = 'testresettoken123'
        reset_token = PasswordResetToken.objects.create(
            user=self.test_user,
            token=token
        )
        
        # Test the confirm view
        uid = urlsafe_base64_encode(force_bytes(self.test_user.pk))
        url = reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
        
        response = self.client.post(
            url,
            data=json.dumps({
                'new_password': 'brandnewpassword'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        
        # Verify password was changed
        user = User.objects.get(username='testuser')
        self.assertTrue(user.check_password('brandnewpassword'))
        
        # Verify token was deleted
        self.assertFalse(PasswordResetToken.objects.filter(token=token).exists())
        
    def test_expired_token(self):
        """Test accessing endpoint with expired token"""
        # Create an expired token
        expired_token = Token.objects.create(
            user=self.test_user,
            key='expiredtoken',
            expires=timezone.now() - timedelta(days=1)  # Expired 1 day ago
        )
        
        response = self.client.get(
            self.profile_url,
            HTTP_AUTHORIZATION=f'Token {expired_token.key}'
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()['success'])
        self.assertIn('invalid', response.json()['message'].lower())