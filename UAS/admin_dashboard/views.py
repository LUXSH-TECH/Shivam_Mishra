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
# from django.utils.decorators import method_decorator
# from accounts.helper import role_required

# Create your views here.

logger = logging.getLogger('user_activity')

class CreateUserView(APIView):
    # permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = CreateUserSerializer
    permission_classes = [IsAuthenticated, IsAdminUser, DynamicRolePermission]
    
    def post(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')
       
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                logger.warning(f"User {auth_user.username} attempted to create a user with an existing email {email} from {ip_address}")
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            new_user = serializer.save()
            logger.info(f"User {auth_user.username} created a new user {new_user.username} (user_id: {new_user.id}) from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Created user {auth_user.username}", ip_address=ip_address)

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
    permission_classes = [IsAuthenticated, IsAdminUser, DynamicRolePermission]
    
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
    permission_classes = [IsAuthenticated, IsAdminUser, DynamicRolePermission]

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
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            role = serializer.save()
            logger.info(f"User {auth_user.username} created a new role {role.name}  from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Created role {role.name}", ip_address=ip_address)

            return Response({'message': 'role created', 'role_id': role.id}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)            
    

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
    serializers = RoleSerializer 
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def put(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '')

        role_id = request.data.get('id')

        if not role_id:
            return Response({'error': 'Role ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        role = get_object_or_404(Role, id=role_id)

        name = request.data.get('name')
        permission_id = request.data.get('permission')

        if Role.objects.filter(name=name).exclude(id=role.id).exists():
            return Response({'error': 'Role with this name already exists'}, status=status.HTTP_400_BAD_REQUEST)

        if name:
            role.name = name  

        if permission_id:
            try:
                permission_instance = Permission.objects.get(id=permission_id)
                role.permission = permission_instance  
            except Permission.DoesNotExist:
                return Response({'error': 'Permission does not exist'}, status=status.HTTP_400_BAD_REQUEST)

        role.save()
        logger.info(f"User {auth_user.username} updated role {role.name}  from {ip_address}")
        UserActivity.objects.create(user=auth_user, action=f"Updated role {role.name} details", ip_address=ip_address)

        serializer = RoleSerializer(role)
        return Response({'message': 'Role updated successfully', 'updated_data': serializer.data}, status=status.HTTP_200_OK)


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
    permission_classes = [IsAuthenticated, IsAdminUser, DynamicRolePermission]

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
            
            if role_instance.name == 'administrator':
                user_instance.is_admin = True

                user_instance.save()
                
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
    permission_classes = [IsAuthenticated, IsAdminUser, DynamicRolePermission]

    def get_object(self):
        user_role_id = self.request.data.get('id')
        return get_object_or_404(UserRoles, id=user_role_id)
    
    def put(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '') 

        try:
            user_role = self.get_object()       
            user = request.data.get('user')
            role = request.data.get('role')
            
            #validating role id
            try:
                role_instance = Role.objects.get(id=role)
            except Role.DoesNotExist:
                raise ValidationError(f"Role with ID {role} does not exist")
                
            #validating user id    
            try:
                user_instance = User.objects.get(id=user)
            except User.DoesNotExist:
                raise ValidationError(f"User with ID {user} does not exist")
            
            #if the role is 'administrator' set is_admin flag
            if role_instance.name == 'administrator':
                user_instance.is_admin = True
            else:
                user_instance.is_admin = False
            
            user_role.user = user_instance
            user_role.role = role_instance

            #save user role
            user_role.save()

            logger.info(f"User {auth_user.username} updated user role of user {user_role.user.username} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Updated user role of user {user_role.user.username} details", ip_address=ip_address)

            serializer = self.serializer_class(user_role)

            return Response({'message': 'user role updated successfully', 'updated_data': serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class DeleteUserRoleView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser, DynamicRolePermission]

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


class ViewAccessListCreateView(APIView):
    """
    API to list and create view access rules.
    """
    queryset = ViewAccess.objects.all()
    serializer_class = ViewAccessSerializer
    permission_classes = [IsAuthenticated, IsAdminUser, DynamicRolePermission]

    def get(self, request):
        accesses = self.queryset()
        serializer = self.serializer_class(accesses, many=True)
        return Response(serializer.data)

    def post(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '') 

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            view_access = serializer.save()

            logger.info(f"User {auth_user.username} created view access '{view_access.view_name}' from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"create view access '{view_access.view_name}'", ip_address=ip_address)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetViewAccessDetailsView(APIView):
    queryset = ViewAccess.objects.all()
    serializer_class = ViewAccessSerializer
    permission_classes = [IsAuthenticated, IsAdminUser, DynamicRolePermission]

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


class ViewAccessUpdateView(APIView):
    """
    API to update the View Access rules
    """
    queryset = ViewAccess.objects.all()
    serializer_class = ViewAccessSerializer
    permission_classes = [IsAuthenticated, DynamicRolePermission]

    def get_object(self):
        view_accesss_id = self.request.data.get('id')
        return get_object_or_404(ViewAccess, id=view_accesss_id)
    
    def put(self, request):
        auth_user = request.user
        ip_address = request.META.get('REMOTE_ADDR', '') 

        try:
            view_access = self.get_object()

            view_name = request.data.get('view_name')
            roles = request.data.data.get('roles')

            view_access.view_name = view_name
            view_access.roles = roles

            view_access.save()
            logger.info(f"User {auth_user.username} updated view access {view_access.view_name} from {ip_address}")
            UserActivity.objects.create(user=auth_user, action=f"Updated view access {view_access.view_name} details", ip_address=ip_address)            

            serializer = self.serializer_class(view_access)

            return Response({'message': 'view access rule updated successfully', 'updated_data': serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
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