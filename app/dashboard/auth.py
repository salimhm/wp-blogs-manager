"""
Authentication utilities for JWT-based login.
"""
import jwt
import datetime
from functools import wraps
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth.models import User
from django.contrib.auth.hashers import check_password


def generate_jwt_token(user):
    """Generate a JWT token for the given user."""
    payload = {
        'user_id': user.id,
        'username': user.username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token


def verify_jwt_token(token):
    """Verify and decode a JWT token. Returns payload or None."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_user_from_token(token):
    """Get User object from JWT token."""
    payload = verify_jwt_token(token)
    if payload:
        try:
            return User.objects.get(id=payload['user_id'])
        except User.DoesNotExist:
            return None
    return None


def jwt_required(view_func):
    """Decorator to require JWT authentication for a view."""
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        # Check for token in cookies
        token = request.COOKIES.get('jwt_token')
        
        if not token:
            return redirect('dashboard:login')
        
        user = get_user_from_token(token)
        if not user:
            response = redirect('dashboard:login')
            response.delete_cookie('jwt_token')
            return response
        
        # Attach user to request
        request.jwt_user = user
        return view_func(request, *args, **kwargs)
    
    return wrapped_view


def authenticate_user(username, password):
    """Authenticate user with username and password."""
    try:
        user = User.objects.get(username=username)
        if user.check_password(password):
            return user
    except User.DoesNotExist:
        pass
    return None
