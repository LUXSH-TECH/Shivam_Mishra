from django.db import models
from accounts.models import *

# Create your models here.

class ViewAccess(models.Model):
    """
    Stores which roles can access which API views dynamically.
    """
    view_name = models.CharField(max_length=255, unique=True)  
    roles = models.ManyToManyField(Role, blank=True)

    def __str__(self):
        return self.view_name
    

class UserActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.action} at {self.timestamp}"