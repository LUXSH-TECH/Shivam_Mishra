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