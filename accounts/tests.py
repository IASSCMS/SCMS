from django.test import TestCase, Client
from django.urls import reverse
import json
from .models import User, Token
from django.utils import timezone
from datetime import timedelta

class AuthenticationTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.profile_url = reverse('profile')
        
    def test_user_registration(self):
        response = self.client.post(
            self.register_url,
            data=json.dumps({
                'username': 'testuser',
                'email': 'test@example.com',
                'password': 'securepassword',
                'first_name': 'Test',
                'last_name': 'User'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])
        
    def test_user_login(self):
        # First create a user
        User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='securepassword'
        )
        
        # Try to login
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
        
    def test_profile_access(self):
        # Create a user
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='securepassword'
        )
        
        # Create a token for the user
        token = Token.objects.create(
            user=user, 
            key='testtoken123',
            expires=timezone.now() + timedelta(days=7)
        )
        
        # Try to access profile with token
        response = self.client.get(
            self.profile_url,
            HTTP_AUTHORIZATION=f'Token {token.key}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['success'])