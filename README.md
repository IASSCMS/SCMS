# SCMS
Intelligent and Smart Supply Chain Management System

# Django Authentication API

A Django-based authentication system with token-based authentication functionality.

## Features

- User registration
- User login with token generation
- Profile access and management
- Password change
- Password reset via email
- Token-based authentication

## Setup and Installation

1. Clone the repository
   ```bash
   git clone https://github.com/iransamarasekara/SCMS.git
   cd SCMS
   ```

2. Create a virtual environment and activate it
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the project root directory and add your environment variables
   (See the example .env file for required variables)

5. Run migrations
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. Create initial roles
   ```bash
   python manage.py shell

   from accounts.models import Role
   Role.objects.create(id=1, name='Admin', description='Administrator with full access')
   Role.objects.create(id=2, name='Regular User', description='Standard user account')
   Role.objects.create(id=3, name='Supplier', description='Product supplier')
   Role.objects.create(id=4, name='Vendor', description='Product vendor')
   Role.objects.create(id=5, name='Warehouse Manager', description='Manages warehouses')
   Role.objects.create(id=6, name='Driver', description='Delivery personnel')
   exit()
   ```

7. Run the development server
   ```bash
   python manage.py runserver
   ```

## API Endpoints

- `/api/v1/register/` - Register a new user
- `/api/v1/login/` - Login and get an authentication token
- `/api/v1/logout/` - Logout and invalidate the token
- `/api/v1/me/` - Get the user profile
- `/api/v1/me/update/` - Update the user profile
- `/api/v1/password/change/` - Change the user password
- `/api/v1/password/reset/` - Request a password reset email
- `/api/v1/password/reset-confirm/<uidb64>/<token>/` - Confirm password reset

### Admin Endpoints
- `/api/v1/admin/users/` - Get all users (admin only)
- `/api/v1/admin/users/<user_id>/` - Update specific user (admin only)
- `/api/v1/admin/users/<user_id>/delete/` - Delete specific user (admin only)

## Authentication

All protected endpoints require token authentication. Include the token in the request header:

```
Authorization: Bearer <your_token>
```

## Testing

Run the tests with:

```bash
python manage.py test
```

## Project Structure

```
project_root/
├── accounts/                 # Main app directory
│   ├── migrations/           # Database migrations
│   ├── models.py             # User, Token, and PasswordResetToken models
│   ├── tests.py              # Authentication tests
│   ├── urls.py               # URL configurations
│   └── views.py              # API views
├── SCMS/                     # Django project settings
│   ├── settings.py           # Project settings
│   ├── urls.py               # Main URL configurations
│   └── wsgi.py               # WSGI configuration
├── .env                      # Environment variables
├── .gitignore                # Git ignore file
├── manage.py                 # Django management script
└── README.md                 # Project documentation
```

## Security Considerations

- The system uses Django's built-in password hashing
- Tokens expire after 7 days
- Password reset tokens expire after 24 hours
- All sensitive data should be stored in the .env file and not committed to version control

## License

[MIT License](LICENSE)
