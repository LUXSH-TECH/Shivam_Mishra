import re
from django.core.exceptions import ValidationError
from accounts.models import User


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