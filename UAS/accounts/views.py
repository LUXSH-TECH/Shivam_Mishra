from django.shortcuts import render
from rest_framework.views import APIView
from accounts.serializer import *
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from rest_framework.response import Response
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.cache import cache
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
# from drf_spectacular.utils import extend_schema

# Create your views here.

class RegisterView(APIView):
    '''
    view for user registration 
    '''
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    
    def post(self,request):
        if request.method == 'POST':
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class LoginView(APIView):
    '''
    View for user login with rate limiter and account locking mechanism
    '''
    MAX_FAILED_ATTEMPTS = 3  # Maximum allowed failed attempts
    LOCKOUT_DURATION = 300  

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # Validate username and password
        if not username or not password:
            return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the username is an email or username
        if '@' in username:
            try:
                user = User.objects.get(email=username)
            except User.DoesNotExist:
                return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if the account is locked in the database
        
        if user.is_locked:
            print(f"locked account attempt by {user.username}")
            return Response({'error': 'Account is locked'}, status=status.HTTP_403_FORBIDDEN)

        # Track failed login attempts in cache
        cache_key = f'login_attempts_{user.username}'
        failed_attempts = cache.get(cache_key, 0)    

        # Authenticate the user
        authenticated_user = authenticate(username=user.username, password=password)

        if authenticated_user is None:
            # Increment failed login attempts in cache
            failed_attempts += 1
            print(f'Failed attempts for user {user.username}: {failed_attempts}')
            cache.set(cache_key, failed_attempts, timeout=self.LOCKOUT_DURATION)

            # Lock the account if failed attempts exceed the threshold
            if failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                user.is_locked = True
                user.save()
                return Response({'error': 'Too many failed attempts. Account is locked.'}, status=status.HTTP_403_FORBIDDEN)

            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Reset failed login attempts on successful login
        cache.delete(cache_key)
        print('successfull login attempt cache key is reset.')

        # Generate tokens
        refresh = RefreshToken.for_user(authenticated_user)
        access_token = str(refresh.access_token)

        # Update last login
        authenticated_user.last_login = timezone.now()
        authenticated_user.save(update_fields=["last_login"])

        # Return response with tokens
        return Response(
            {
                'status': 'login successful',
                'refresh': str(refresh),
                'access': access_token,
            },
            status=status.HTTP_200_OK
        )
    

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            user.save()

            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            # Send password reset email
            serializer.save()
            return Response({"message": "A password reset link is sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name='dispatch')
class PasswordResetView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, uidb64, token):
        data = request.data.copy()  
        data.update({"uidb64": uidb64, "token": token})  
        
        serializer = PasswordResetSerializer(data=data)
        if serializer.is_valid():
            # Reset the user's password
            serializer.save()
            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    def post(self, request):
         try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response({'message': 'Successfully logged out.'},status=status.HTTP_200_OK)
         except Exception as e:
             return Response(status=status.HTTP_400_BAD_REQUEST)

# class LogoutView(APIView):

#     def post(self, request):
#         try:
#             auth_header = request.headers.get('Authorization')

#             if auth_header and auth_header.startswith('Bearer '):
#                 refresh_token = auth_header.split(' ')[1]
#                 token = RefreshToken(refresh_token)
#                 token.blacklist()
                
#                 return Response({'message': 'You have been logged out'}, status=status.HTTP_200_OK)
#             else:
#                 return Response({'error': 'Authorization header missing or invalid'}, status=status.HTTP_400_BAD_REQUEST)
        
#         except Exception as e:
#             return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


def register_view(request):
    return render(request, 'accounts/register.html')

def login_view(request):
    return render(request, 'accounts/login.html')

def request_reset_password_view(request):
    return render(request, 'accounts/request_reset_passowrd.html')

def reset_password_view(request):
    return render(request, 'accounts/reset_password.html')

def logout_view(request):
    return render(request, 'accounts/logout.html')

