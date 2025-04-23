from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from datetime import timedelta

class Role(models.Model):
    """
    Role model for user roles
    1 = Admin
    2 = Regular User
    3 = Supplier
    4 = Vendor
    5 = Warehouse Manager
    6 = Driver
    """
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name

class User(AbstractUser):
    """
    Extended User model
    """
    email = models.EmailField(unique=True)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, related_name='users')
    is_verified = models.BooleanField(default=False)
    phone = models.CharField(max_length=20, blank=True, null=True)
    
    # Define REQUIRED_FIELDS for createsuperuser command
    REQUIRED_FIELDS = ['email']
    
    class Meta:
        db_table = 'auth_user'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
    
    def __str__(self):
        return self.username
    
    @property
    def role_id(self):
        return self.role.id if self.role else None
    
    @role_id.setter
    def role_id(self, value):
        try:
            self.role = Role.objects.get(id=value)
        except Role.DoesNotExist:
            # Default to regular user if role doesn't exist
            self.role = Role.objects.get_or_create(id=2, name='Regular User')[0]

class PasswordResetToken(models.Model):
    """
    Password reset token model
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=100)
    created = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'auth_password_reset_token'
        verbose_name = 'Password Reset Token'
        verbose_name_plural = 'Password Reset Tokens'
    
    def __str__(self):
        return f"{self.user.username} - {self.token[:10]}..."
        
    def is_valid(self):
        # Token valid for 24 hours
        return self.created > timezone.now() - timedelta(hours=24)

# Role-specific models that extend user data
class Supplier(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    company_name = models.CharField(max_length=255)
    business_type = models.CharField(max_length=100)
    tax_id = models.CharField(max_length=50)
    
    def __str__(self):
        return f"Supplier: {self.user.username} ({self.company_name})"

class Vendor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    shop_name = models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    business_license = models.CharField(max_length=50)
    
    def __str__(self):
        return f"Vendor: {self.user.username} ({self.shop_name})"

class WarehouseManager(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    warehouse_id = models.CharField(max_length=50)
    department = models.CharField(max_length=100)
    
    def __str__(self):
        return f"Warehouse Manager: {self.user.username} ({self.warehouse_id})"

class Driver(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    license_number = models.CharField(max_length=50)
    vehicle_type = models.CharField(max_length=100)
    
    def __str__(self):
        return f"Driver: {self.user.username} ({self.license_number})"