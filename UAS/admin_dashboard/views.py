from django.shortcuts import render, get_object_or_404
from accounts.models import *
from accounts.serializer import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from admin_dashboard.serializers import *
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from admin_dashboard.permissions import DynamicRolePermission
import logging
from utils.pagination import CustomPagination
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import OrderingFilter
import csv
from django.http import HttpResponse
from django.db.models import Q
from django.utils.dateparse import parse_date
# from django.utils.decorators import method_decorator
# from accounts.helper import role_required

# Create your views here.

logger = logging.getLogger('user_activity')

class CreateUserView(APIView):
    queryset = User.objects.all()
    serializer_class = CreateUserSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]
    
    def post(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')
       
        serializer = self.serializer_class(data=request.data)
        
        if (serializer.is_valid()):
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                logger.warning(f"User {auth_user.username} attempted to create a user with an existing email {email} from {ip_address}")
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            new_user = serializer.save()
            logger.info(f"User {auth_user.username} created a new user {new_user.username} (user_id: {new_user.id}) from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Created user {new_user.username}", ip_address=ip_address)

            return Response({'message': 'User created successfully', 'user_id': new_user.id}, status=status.HTTP_201_CREATED)
        
        logger.error(f"User {auth_user.username} failed to create user from {ip_address}. Errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  
    

class UserListView(generics.ListAPIView):
    queryset = User.objects.filter(is_superuser=False, is_user=True)  # Exclude superusers
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get(self, request, *args, **kwargs):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        logger.info(f"User {auth_user.username} fetched the user list from {ip_address}")
        UserActivity.objects.create(user=auth_user, action="Fetched user list", ip_address=ip_address)

        return super().get(request, *args, **kwargs) 


class GetUserDetailView(APIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]
    
    def get(self, request, id):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            user = User.objects.get(id=id, is_superuser=False, is_user=True)
            
            logger.info(f"User {auth_user.username} fetched the details of user {user.username} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Fetched details of {user.username}", ip_address=ip_address)

            user_details = {
                'username': user.username,
                'full_name': user.full_name,
                'email': user.email,
                'is_active': user.is_active,
                'is_inactive': user.is_inactive,
                'is_locked': user.is_locked,
                'created_at': user.created_at,
                'updated_at': user.updated_at,
            }

            return Response({'message': 'user details fetched successfully', 'user': user_details}, status=status.HTTP_200_OK)
        
        except User.DoesNotExist:
            return Response({"Status": "Failed", "Reason": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        

class UpdateUserDetailsView(APIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def put(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        user_id = request.data.get('id')
        username = request.data.get('username')
        full_name = request.data.get('name')
        email = request.data.get('email')
        is_active = request.data.get('is_active')
        is_inactive = request.data.get('is_inactive')
        is_locked = request.data.get('is_locked')

        if not user_id:
            return Response({"Status": "Failed", "Reason": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the user instance by ID
            user = User.objects.get(id=user_id, is_superuser=False, is_user=True)
        except User.DoesNotExist:
            # Return error if user does not exist
            return Response({"Status": "Failed", "Reason": "User not found"}, status=status.HTTP_404_NOT_FOUND)
       
        user.username = username
        user.full_name = full_name
        user.email = email
        user.is_active = is_active
        user.is_inactive = is_inactive
        user.is_locked = is_locked
        
        user.full_clean()
        user.save()

        logger.info(f"User {auth_user.username} updated user {user.username} (user_id: {id}) from {ip_address}")
        UserActivity.objects.create(user=auth_user, action=f"Updated user {user.username} details", ip_address=ip_address)

        return Response({'message': 'user details updated successfully', 'user_id': user_id}, status=status.HTTP_200_OK)


class ToggleMFAView(APIView):
    """
    Allows an admin user to enable or disable MFA for a specific user.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    # permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        auth_user = request.user
        user_id = request.data.get('id')
        is_mfa_enabled = request.data.get('is_mfa_enabled')

        if user_id is None or is_mfa_enabled is None:
            return Response({'error':'user ID and mfa status are required'},status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'error':'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        user.is_mfa_enabled = is_mfa_enabled
        user.save()

        status_msg = "enabled" if is_mfa_enabled else "disabled"
        # logger.info(f"User {auth_user.username} {status_msg} MFA for user {user.username}")

        return Response({"message": f"MFA {status_msg} successfully for user {user.username}."}, status=status.HTTP_200_OK)


class DeleteUserView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser, DynamicRolePermission]
    
    def delete(self, request, id):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            user = User.objects.get(id=id)

            if user.id == 1 or user.is_superuser:
                return Response({'error': 'Cannot delete user'}, status=status.HTTP_403_FORBIDDEN)
            
        except User.DoesNotExist:
            return Response({'error': 'user not found'}, status=status.HTTP_404_NOT_FOUND)
        
        user.delete()
        logger.info(f"User {auth_user.username} deleted user {user.username} (user_id: {id}) from {ip_address}")
        UserActivity.objects.create(user=auth_user, action=f"Deleted user {user.username}", ip_address=ip_address)

        return Response({'message': 'user deleted'}, status=status.HTTP_202_ACCEPTED)
    

class CreatePermissionView(APIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def post(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            
            permission = serializer.save()
            logger.info(f"User {auth_user.username} created a new permission {permission.name}  from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Created permission {permission.name}", ip_address=ip_address)

            return Response({'message': 'permission created', 'permission_id': permission.id}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class PermissionListView(generics.ListAPIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get(self, request, *args, **kwargs):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        logger.info(f"User {auth_user.username} fetched the permission list from {ip_address}")
        UserActivity.objects.create(user=auth_user, action="Fetched permission list", ip_address=ip_address)

        return super().get(request, *args, **kwargs) 
    

class GetPermissionDetailsView(APIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get(self, request, id):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            permission = Permission.objects.get(id=id)

            logger.info(f"User {auth_user.username} fetched the details of permission {permission.name} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Fetched details of {permission.name}", ip_address=ip_address)

            permission_details = {
                'name': permission.name,
                'codename': permission.codename,
                'created_at': permission.created_at,
                'updated_at': permission.updated_at
            }
            
            return Response({'permission_details': permission_details}, status=status.HTTP_200_OK)
        
        except Permission.DoesNotExist:
            return Response({'status': 'failed', 'reason': 'permission not found'}, status=status.HTTP_400_BAD_REQUEST)
        
    
class UpdatePermissionView(APIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get_object(self):
        permission_id = self.request.data.get('id')
        return get_object_or_404(Permission, id=permission_id)
    
    def put(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            permission = self.get_object()

            name = request.data.get('name')
            codename = request.data.get('codename')

            permission.name = name
            permission.codename = codename

            permission.save()
            logger.info(f"User {auth_user.username} updated permission {permission.name}  from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Updated permission {permission.name} details", ip_address=ip_address)

            serializer = self.serializer_class(permission)

            return Response({'message': 'updated successfully', 'updated_data': serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class DeletePermissionView(APIView):
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def delete(self, request, id):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            permission = Permission.objects.get(id=id)

        except Permission.DoesNotExist:
            return Response({'error': 'permission not found'}, status=status.HTTP_404_NOT_FOUND)
        
        permission.delete()
        logger.info(f"User {auth_user.username} deleted permission {permission.name} from {ip_address}")
        UserActivity.objects.create(user=auth_user, action=f"Deleted permission {permission.name}", ip_address=ip_address)

        return Response({'message': 'permission deleted'}, status=status.HTTP_202_ACCEPTED)        
    

class CreateRoleView(APIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        if serializer.is_valid():
            name = serializer.validated_data.get('name')
            permissions = serializer.validated_data.get('permissions', [])

            try:
                # Validate permissions
                permission_instances = Permission.objects.filter(id__in=permissions)
                if len(permission_instances) != len(permissions):
                    raise ValidationError({"permissions": "One or more permissions do not exist"})

                # Create the role
                role = Role.objects.create(name=name)
                role.permission.set(permission_instances)

                logger.info(f"User {auth_user.username} created a new role '{role.name}' with permissions from {ip_address}")
                UserActivity.objects.create(user=auth_user, action=f"Created role '{role.name}'", ip_address=ip_address)

                serializer = self.serializer_class(role)
                return Response({'message': 'role created', 'role_id': role.id, 'data': serializer.data}, status=status.HTTP_201_CREATED)

            except ValidationError as e:
                logger.warning(f"User {auth_user.username} failed to create role due to {e.detail}")
                return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)

        logger.warning(f"User {auth_user.username} failed to create role due to {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RoleListView(generics.ListAPIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get(self, request, *args, **kwargs):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        logger.info(f"User {auth_user.username} fetched the role list from {ip_address}")
        UserActivity.objects.create(user=auth_user, action="Fetched role list", ip_address=ip_address)

        return super().get(request, *args, **kwargs) 
    

class GetRoleDetailsView(APIView):
    queryset = Role.objects.all()
    serializers = RoleSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]
    
    def get(self, request, id):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            role = Role.objects.get(id=id)
            logger.info(f"User {auth_user.username} fetched the details of role {role.name} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Fetched details of {role.name}", ip_address=ip_address)

            role_details = {
                'name': role.name,
                'permission': role.permission.name,
                'created_at': role.created_at,
                'updated_at': role.updated_at,
            }

            return Response({'role_details': role_details}, status=status.HTTP_200_OK)
        
        except Role.DoesNotExist:
            return Response({'status': 'failed', 'reason': 'role not found'}, status=status.HTTP_400_BAD_REQUEST)
        

class UpdateRoleView(APIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get_object(self):
        return get_object_or_404(Role, id=self.request.data.get('id'))

    def put(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            role = self.get_object()
            name = request.data.get('name')
            permission_ids = request.data.get('permissions', [])

            if name and Role.objects.filter(name=name).exclude(id=role.id).exists():
                return Response({'error': 'Role with this name already exists'}, status=status.HTTP_400_BAD_REQUEST)

            if name:
                role.name = name

            if permission_ids:
                try:
                    permissions = Permission.objects.filter(id__in=permission_ids)
                    if len(permissions) != len(permission_ids):
                        raise Permission.DoesNotExist
                    role.permission.set(permissions)
                except Permission.DoesNotExist:
                    return Response({'error': 'One or more permissions do not exist'}, status=status.HTTP_400_BAD_REQUEST)

            role.save()
            logger.info(f"User {auth_user.username} updated role {role.name} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Updated role {role.name} details", ip_address=ip_address)

            serializer = self.serializer_class(role)
            return Response({'message': 'Role updated successfully', 'updated_data': serializer.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteRoleView(APIView):
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def delete(self, request, id):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            role = Role.objects.get(id=id)
        
        except Role.DoesNotExist:
            return Response({'error': 'role does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        role.delete()
        logger.info(f"User {auth_user.username} deleted role {role.name} from {ip_address}")
        UserActivity.objects.create(user=auth_user, action=f"Deleted role {role.name}", ip_address=ip_address)        

        return Response({'message': 'role deleted'}, status=status.HTTP_202_ACCEPTED)
    

class CreateUserRoleView(APIView):
    queryset = UserRoles.objects.all()
    serializer_class = UserRoleSerialiser
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    # def post(self, request):
    #     serializer = self.serializer_class(data=request.data)

    #     if serializer.is_valid():
    #         user_role = serializer.save()

    #         return Response({'message': 'user role created', 'user_role_id': user_role.id}, status=status.HTTP_201_CREATED)
        
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)            
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            # user = request.data.get('user')
            # role = request.data.get('role')
            auth_user = request.user
            ip_address = request.META.get('REMOTE_ADDR', '')      

            user = serializer.validated_data['user']
            role = serializer.validated_data['role']

            try:
                role_instance = Role.objects.get(id=role)
            except Role.DoesNotExist:
                raise ValidationError({"role": "Role does not exist"})
                
            try:
                user_instance = User.objects.get(id=user)
            except User.DoesNotExist:
                raise ValidationError({"user": "User does not exist"})
                
            user_role = UserRoles.objects.create(
                role = role_instance,
                user = user_instance
            )
            
            logger.info(f"User {auth_user.username} assigned role '{role_instance.name}' to user '{user_instance.username}' from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Assigned role '{role_instance.name}' to user {user_instance.username}", ip_address=ip_address)

            serializer.save()
            return Response({'message': 'user role created', 'user_role_id': user_role.id}, status=status.HTTP_201_CREATED)
        
        logger.warning(f"User {auth_user.username} failed to create user role due to  {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class UserRolesListView(generics.ListAPIView):
    queryset = UserRoles.objects.all()
    serializer_class = UserRoleSerialiser
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get(self, request, *args, **kwargs):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        logger.info(f"User {auth_user.username} fetched the user_role list from {ip_address}")
        UserActivity.objects.create(user=auth_user, action="Fetched user_role list", ip_address=ip_address)

        user_roles = self.queryset.select_related('user', 'role')  # Fetch related user and role data
        data = [
            {
                'id': user_role.id,
                'user': user_role.user.username,  # Return username
                'role': user_role.role.name      # Return role name
            }
            for user_role in user_roles
        ]
        return Response(data, status=status.HTTP_200_OK)
    

class GetUserRoleDetailsView(APIView):
    queryset = UserRoles.objects.all()
    serializer_class = UserRoleSerialiser
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get(self, request, id):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '') 

        try:
            user_role = UserRoles.objects.get(id=id)

            logger.info(f"User {auth_user.username} fetched the details of user role of user {user_role.user.username} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Fetched details of user role of user {user_role.user.username}", ip_address=ip_address)

            user_role_details = {
                'user': user_role.user.username,
                'role': user_role.role.name
            }

            return Response({'user_role_details': user_role_details}, status=status.HTTP_200_OK)
        
        except UserRoles.DoesNotExist:
            return Response({'status': 'failed', 'reason': 'user role not found'}, status=status.HTTP_400_BAD_REQUEST)
    

class UpdateUserRoleView(APIView):
    queryset = UserRoles.objects.all()
    serializer_class = UserRoleSerialiser
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get_object(self):
        return get_object_or_404(UserRoles, id=self.request.data.get('id'))
    
    def put(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            user_role = self.get_object()
            role_instance = get_object_or_404(Role, id=request.data.get('role'))

            user_role.role = role_instance
            user_role.save()

            logger.info(f"User {auth_user.username} updated role for user {user_role.user.username} to {role_instance.name} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Updated role for user {user_role.user.username} to {role_instance.name}", ip_address=ip_address)

            return Response({'message': 'User role updated successfully', 'updated_data': self.serializer_class(user_role).data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class DeleteUserRoleView(APIView):
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def post(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '') 

        try:
            user_role = UserRoles.objects.get(id)
        except UserRoles.DoesNotExist:
            return Response({'message': 'user role does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        user_role.delete()
        logger.info(f"User {auth_user.username} deleted user role of user {user_role.user.username} from {ip_address}")
        UserActivity.objects.create(user=auth_user, action=f"Deleted user role of user {user_role.user.username}", ip_address=ip_address) 

        return Response({'message': 'user role deleted'}, status=status.HTTP_202_ACCEPTED)


class ViewAccessCreateView(APIView):
    """
    API to create view access rules.
    """
    queryset = ViewAccess.objects.all()
    serializer_class = ViewAccessSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def post(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        data = request.data
        roles = data.get('roles', [])

        if not isinstance(roles, list):
            return Response({'error': 'Roles must be a list of role IDs.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            role_instances = Role.objects.filter(id__in=roles)
            if len(role_instances) != len(roles):
                return Response({'error': 'Some roles do not exist.'}, status=status.HTTP_400_BAD_REQUEST)

            data['roles'] = role_instances  # Replace role IDs with actual role instances
            serializer = self.serializer_class(data=data)

            if serializer.is_valid():
                view_access = serializer.save()
                logger.info(f"User {auth_user.username} created view access '{view_access.view_name}' from {ip_address}")
                UserActivity.objects.create(user=auth_user, action=f"Created view access '{view_access.view_name}'", ip_address=ip_address)
                return Response(serializer.data, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error creating view access: {str(e)}")
            return Response({'error': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetViewAccessDetailsView(APIView):
    queryset = ViewAccess.objects.all()
    serializer_class = ViewAccessSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get(self, request, id):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        try:
            view_access = ViewAccess.objects.get(id=id)
            logger.info(f"User {auth_user.username} fetched the details of view access{view_access.view_name} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Fetched details of view access {view_access.view_name}", ip_address=ip_address)

            view_access_details = {
                'view_name': view_access.view_name,
                'roles': view_access.roles.name 
            }

            return Response({'view_access_details': view_access_details}, status=status.HTTP_200_OK)
        
        except ViewAccess.DoesNotExist:
            return Response({'status': 'failed', 'reason': 'view access rule not found'}, status=status.HTTP_400_BAD_REQUEST)   


class ViewAccessListView(generics.ListAPIView):
    queryset = ViewAccess.objects.all()
    serializer_class = ViewAccessSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get(self, request, *args, **kwargs):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        logger.info(f"User {auth_user.username} fetched the view access list from {ip_address}")
        UserActivity.objects.create(user=auth_user, action="Fetched view access list", ip_address=ip_address)

        view_access_list = self.queryset.prefetch_related('roles')  # Fetch related roles data
        data = [
            {
                'id': view_access.id,
                'view_name': view_access.view_name,  # Return view name
                'roles': [role.name for role in view_access.roles.all()]  # Return list of role names
            }
            for view_access in view_access_list
        ]
        return Response(data, status=status.HTTP_200_OK)


class ViewAccessUpdateView(APIView):
    """
    API to update the View Access rules
    """
    queryset = ViewAccess.objects.all()
    serializer_class = ViewAccessSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get_object(self):
        # Get the view access object by ID from the request data
        view_accesss_id = self.request.data.get('id')
        return get_object_or_404(ViewAccess, id=view_accesss_id)
    
    def put(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '') 

        try:
            # Fetch the view access object to be updated
            view_access = self.get_object()

            role_instance  = get_object_or_404(Role, id=request.data.get('role')) 
            view_access.roles = role_instance

            # Save the updated view access object
            view_access.save()
            logger.info(f"User {auth_user.username} updated view access {view_access.view_name} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Updated view access {view_access.view_name} details", ip_address=ip_address)            

            serializer = self.serializer_class(view_access)
            return Response({'message': 'view access rule updated successfully', 'updated_data': serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            # Handle any exceptions that occur and return an error response
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class ViewAccessDeleteView(APIView):
    permission_classes = [IsAuthenticated, DynamicRolePermission]
    
    def delete(self, request, id):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '') 

        try:
            view_access = ViewAccess.objects.get(id=id)
        except ViewAccess.DoesNotExist:
            return Response({'message':'view access rule does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        view_access.delete()
        logger.info(f"User {auth_user.username} deleted view access {view_access.view_name} from {ip_address}")
        UserActivity.objects.create(user=auth_user, action=f"Deleted view access {view_access.view_name}", ip_address=ip_address)    

        return Response({'message': 'veiw access rule deleted succesfully'}, status=status.HTTP_202_ACCEPTED)
    

class UserActivityListView(generics.ListAPIView):
    """
    API for filtering audit logs.
    Supports filters: user_id, start_date, end_date, action.
    """
    serializer_class = UserActivitySerializer
    pagination_class = CustomPagination
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    ordering_fields = ['timestamp']  # Allow sorting by timestamp
    ordering = ['-timestamp']  # Default: Newest first

    def get_queryset(self):
        queryset = UserActivity.objects.all()
        params = self.request.query_params

        # Extract parameters
        start_date = params.get('start_date')
        end_date = params.get('end_date')
        user_id = params.get('user_id')  
        action = params.get('action')

        # Filter by date range
        if start_date:
            parsed_start_date = parse_date(start_date)
            if parsed_start_date:
                queryset = queryset.filter(timestamp__date__gte=parsed_start_date)

        if end_date:
            parsed_end_date = parse_date(end_date)
            if parsed_end_date:
                queryset = queryset.filter(timestamp__date__lte=parsed_end_date)

        if user_id:
            queryset = queryset.filter(user__id=user_id) 

        # Filter by action keyword
        if action:
            queryset = queryset.filter(action__icontains=action)

        return queryset


class UserActivityCSVReportView(UserActivityListView):
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get(self, request, *args, **kwargs):
        queryset = self.get_queryset()

        # Creating the HttpResponse object with CSV header
        response = HttpResponse(content_type='text/csv')
        current_date = timezone.now().strftime('%Y-%m-%d')
        response['Content-Disposition'] = f'attachment; filename="user_activity_report_{current_date}.csv"'

        write = csv.writer(response)
        write.writerow(['User', 'Action', 'IP Address', 'Timestamp'])

        for activity in queryset:
            write.writerow([activity.user.username, activity.action, activity.ip_address, activity.timestamp])

        return response
    

#<-----     views to serve admin side user templates     ----->
def create_user(request):
    return render(request, 'admin_panel/user_management/create_user.html')

def user_list(request):
    return render(request, 'admin_panel/user_management/user_list.html')

def user_detail(request):
    return render(request, 'admin_panel/user_management/user_details.html')

def toggle_mfa(request):
    users = User.objects.filter(is_superuser=False, is_user=True)  # Fetch non-superuser users
    return render(request, 'admin_panel/user_management/toggle_mfa.html', {'users': users})

def delete_user(request):
    return render(request, 'admin_panel/user_management/delete_user.html')

#<-----     views to serve admin side permission templates     ----->
def create_permission(request):
    return render(request, 'admin_panel/permissions/create_permission.html')

def permission_list(request):
    return render(request, 'admin_panel/permissions/permission_list.html')

def permission_details(request):
    return render(request, 'admin_panel/permissions/permission_details.html')

def delete_permission(request):
    return render(request, 'admin_panel/permissions/delete_permission.html')

#<-----     views to serve admin side role templates     ----->
def create_role(request):
    return render(request, 'admin_panel/roles/create_role.html')

def role_list(request):
    return render(request, 'admin_panel/roles/role_list.html')

def role_details(request):
    return render(request, 'admin_panel/roles/role_details.html')

def delete_role(request):    
    return render(request, 'admin_panel/roles/delete_role.html')

#<-----     views to serve admin side user_role templates     ----->
def assign_user_role(request):
    users = User.objects.filter(is_superuser=False, is_user=True)  # Fetch non-superuser users
    roles = Role.objects.all()  # Fetch all roles
    return render(request, 'admin_panel/userrole/assign_user_role.html', {'users': users, 'roles': roles})

def user_role_list(request):
    return render(request, 'admin_panel/userrole/user_role_list.html')

def user_role_details(request):
    return render(request, 'admin_panel/userrole/user_role_details.html')

def delete_user_role(request):
    return render(request, 'admin_panel/userrole/delete_user_role.html')

#<-----     views to serve admin side view_access templates     ----->

def create_view_access(request):
    roles = Role.objects.all()  # Fetch all roles
    return render(request, 'admin_panel/viewaccess/create_view_access.html', {'roles': roles})

def view_access_list(request):
    # roles = Role.objects.all()
    return render(request, 'admin_panel/viewaccess/view_access_list.html')# {'roles': roles})

def view_access_details(request):
    return render(request, 'admin_panel/viewaccess/view_access_details.html')

def delete_view_access(request):
    return render(request, 'admin_panel/viewaccess/delete_view_access.html')

def user_activity_list(requset):
    return render(requset, 'admin_panel/useractivity/user_activity_list.html')