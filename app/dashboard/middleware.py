"""
JWT Authentication Middleware for Dashboard.
"""
from django.shortcuts import redirect
from .auth import get_user_from_token


class JWTAuthMiddleware:
    """Middleware to require JWT authentication for dashboard views."""
    
    # Paths that don't require authentication
    PUBLIC_PATHS = [
        '/login/',
        '/admin/',
        '/static/',
    ]
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Check if path is public
        for path in self.PUBLIC_PATHS:
            if request.path.startswith(path):
                return self.get_response(request)
        
        # Check for JWT token
        token = request.COOKIES.get('jwt_token')
        
        if not token:
            return redirect('dashboard:login')
        
        user = get_user_from_token(token)
        
        if not user:
            response = redirect('dashboard:login')
            response.delete_cookie('jwt_token')
            return response
        
        # Attach user to request for use in views
        request.jwt_user = user
        
        return self.get_response(request)
