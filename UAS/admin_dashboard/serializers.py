from rest_framework import serializers
from accounts.models import *
from admin_dashboard.models import *


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = '__all__'
        read_only_fields = ['created_at']

    
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'
        read_only_fields = ['created_at']


class UserRoleSerialiser(serializers.ModelSerializer):
    class Meta:
        model = UserRoles
        fields = '__all__'


class ViewAccessSerializer(serializers.ModelSerializer):
    class Meta:
        model = ViewAccess
        fields = '__all__'