from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta

# Create your models here.
class User(AbstractUser):
    # AbstractUser already has username, email, password, first_name, last_name, is_active, is_staff, date_joined
    # We need to define REQUIRED_FIELDS which are fields required when creating a superuser
    # It should be a list of field names that cannot be blank (besides the username field)
    REQUIRED_FIELDS = ['email']
    
    # We don't need to define any additional fields since AbstractUser already has the ones we need
    # If you want to add any additional fields, you can do so here
    
    def __str__(self):
        return self.username

class Token(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    key = models.CharField(max_length=40, unique=True)
    created = models.DateTimeField(auto_now_add=True)
    expires = models.DateTimeField()
    
    def __str__(self):
        return f"{self.user.username} - {self.key}"
    
    def is_valid(self):
        return self.expires > timezone.now()

class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100)
    created = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.token}"
        
    def is_valid(self):
        # Token valid for 24 hours
        return self.created > timezone.now() - timedelta(hours=24)