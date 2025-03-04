import re
from django.core.exceptions import ValidationError
from accounts.models import User, UserRoles
from functools import wraps
from django.http import JsonResponse
from rest_framework import status


def custom_password_validator(password):
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain at least one uppercase letter')
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain at least one smallcase letter')
    if not re.search(r'[0-9]', password):
        raise ValidationError('Password must contain at least one numerical character')
    if not re.search(r'[!@#$%&*]', password):
        raise ValidationError('Passoword must contain at least one special characters')
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long')


# def role_required(allowed_roles):
#     """
#     Decorator to restrict access based on user roles.
#     """
#     def decorator(view_func):
#         @wraps(view_func)
#         def _wrapped_view(request, *args, **kwargs):
#             user_roles = UserRoles.objects.filter(user=request.user).values_list('role__name', flat=True)

#             # Check if the user has any of the allowed roles
#             if any(role in user_roles for role in allowed_roles):
#                 return view_func(request, *args, **kwargs)
#             return JsonResponse({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)
#         return _wrapped_view
#     return decorator