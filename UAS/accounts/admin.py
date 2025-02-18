from django.contrib import admin
from accounts.models import*

# Register your models here.

admin.site.register(User)
admin.site.register(Role)
admin.site.register(UserRoles)
admin.site.register(Permission)