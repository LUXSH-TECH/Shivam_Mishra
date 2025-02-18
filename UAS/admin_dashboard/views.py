from django.shortcuts import render, get_object_or_404
from accounts.models import *
from accounts.serializer import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from admin_dashboard.serializers import *
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated

# Create your views here.

class CreateUserView(APIView):
    # permission_classes = [IsAuthenticated]
    queryset = User.objects.all()
    serializer_class = CreateUserSerializer
    
    def post(self, request):
       
        serializer = self.serializer_class(data=request.data)
        
        if serializer.is_valid():
            
            email = serializer.validated_data['email']
            if User.objects.filter(email=email).exists():
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            user = serializer.save()

            return Response({'message': 'User created successfully', 'user_id': user.id}, status=status.HTTP_201_CREATED)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)  
    

class UserListView(generics.ListAPIView):
    queryset = User.objects.filter(is_superuser=False,is_user=True)  # Exclude superusers
    serializer_class = UserSerializer


class GetUserDetailView(APIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def get(self, request, id):
        try:
            user = User.objects.get(id=id, is_superuser=False, is_user=True)

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

    def put(self, request):
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

        return Response({'message': 'user details updated successfully', 'user_id': user_id}, status=status.HTTP_200_OK)


class DeleteUserView(APIView):
    
    def delete(self, request, id):
        try:
            user = User.objects.get(id=id)

            if user.id == 1 or user.is_superuser:
                return Response({'error': 'Cannot delete user'}, status=status.HTTP_403_FORBIDDEN)
            
        except User.DoesNotExist:
            return Response({'error': 'user not found'}, status=status.HTTP_404_NOT_FOUND)
        
        user.delete()

        return Response({'message': 'user deleted'}, status=status.HTTP_202_ACCEPTED)
    

class CreatePermissionView(APIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            
            permission = serializer.save()

            return Response({'message': 'permission created', 'permission_id': permission.id}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class GetPermissionDetailsView(APIView):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

    def get(self, request, id):
        try:
            permission = Permission.objects.get(id=id)

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

    def get_object(self):
        permission_id = self.request.data.get('id')
        return get_object_or_404(Permission, id=permission_id)
    
    def put(self, request):
        try:
            permission = self.get_object()

            name = request.data.get('name')
            codename = request.data.get('codename')

            permission.name = name
            permission.codename = codename

            permission.save()

            serializer = self.serializer_class(permission)

            return Response({'message': 'updated successfully', 'updated_data': serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class DeletePermissionView(APIView):

    def delete(self, request, id):
        try:
            permission = Permission.objects.get(id=id)

        except Permission.DoesNotExist:
            return Response({'error': 'permission not found'}, status=status.HTTP_404_NOT_FOUND)
        
        permission.delete()

        return Response({'message': 'permission deleted'}, status=status.HTTP_202_ACCEPTED)        
    

class CreateRoleView(APIView):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            role = serializer.save()

            return Response({'message': 'role created', 'role_id': role.id}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)            


class GetRoleDetailsView(APIView):
    queryset = Role.objects.all()
    serializers = RoleSerializer

    def get(self, request, id):
        try:
            role = Role.objects.get(id=id)

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
    
    def get_object(self):
        role_id = self.request.data.get('id')
        return get_object_or_404(Role, id=role_id)
    
    def put(self, request):
        try:
            role = self.get_object()

            name = request.data.get('name')
            permission = request.data.get('permission')

            if Role.objects.filter(name=name).exclude(id=role.id).exists():
                return Response({'error': 'name already exists'}, status=status.HTTP_400_BAD_REQUEST)
            
            if permission:
                try:
                    permission_instance = Permission.objects.get(id=permission)
                    role.permission = permission_instance
                except Permission.DoesNotExist:
                    raise ValidationError(f'permission does not exist')
                
            role.name = name

            role.save()

            serializer = self.serializer_class(role)

            return Response({'message': 'role updated successfully', 'updated_data': serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DeleteRoleView(APIView):

    def delete(self, request, id):
        try:
            role = Role.objects.get(id=id)
        
        except Role.DoesNotExist:
            return Response({'error': 'role does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        role.delete()

        return Response({'message': 'role deleted'}, status=status.HTTP_202_ACCEPTED)
    

class CreateUserRoleView(APIView):
    queryset = UserRoles.objects.all()
    serializer_class = UserRoleSerialiser

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user_role = serializer.save()

            return Response({'message': 'user role created', 'user_role_id': user_role.id}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)            
    

class GetUserRoleDetailsView(APIView):
    queryset = UserRoles.objects.all()
    serializer_class = UserRoleSerialiser

    def get(self, request, id):
        try:
            user_role = UserRoles.objects.get(id=id)

            user_role_details = {
                'user': user_role.user.username,
                'role': user_role.role
            }

            return Response({'user_role_details': user_role_details}, status=status.HTTP_200_OK)
        
        except UserRoles.DoesNotExist:
            return Response({'status': 'failed', 'reason': 'user role not found'}, status=status.HTTP_400_BAD_REQUEST)