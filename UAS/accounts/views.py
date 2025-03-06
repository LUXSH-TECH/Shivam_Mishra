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
from django.core.mail import send_mail
from random import randint
from allauth.account.signals import user_logged_in
from django.dispatch import receiver
from allauth.account.utils import perform_login
from allauth.account.models import EmailAddress
from allauth.account.utils import send_email_confirmation
from allauth.account.views import ConfirmEmailView
from django.http import JsonResponse
import logging
from admin_dashboard.models import *

logger = logging.getLogger('user_activtiy')
# Create your views here.

# class RegisterView(APIView):
#     '''
#     view for user registration 
#     '''
#     queryset = User.objects.all()
#     serializer_class = UserRegisterSerializer
    
#     def post(self,request):
#         if request.method == 'POST':
#             serializer = self.serializer_class(data=request.data)
#             if serializer.is_valid():
#                 serializer.save()
#                 return Response(serializer.data, status=status.HTTP_201_CREATED)
#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class RegisterView(APIView):
    """
    View for user registration with email verification using django-allauth.
    """
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            # Save the user instance
            user = serializer.save()
            # Trigger email confirmation
            send_email_confirmation(request, user)
            return Response(
                {'detail': 'Registration successful. Verification email sent.'},
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class CustomConfirmEmailView(ConfirmEmailView):
    def get(self, *args, **kwargs):
        self.object = self.get_object()  # Retrieves the email confirmation object
        self.object.confirm(self.request)
        return JsonResponse({'detail': 'Email confirmed successfully.'})
        

class LoginView(APIView):
    '''
    Login view  with MFA using otp through user email and
    rate limiter and account locking mechanism.
    '''
    MAX_FAILED_ATTEMPTS = 3  # Maximum allowed failed attempts
    LOCKOUT_DURATION = 300  

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        ip_address = request.Meta.get('REMOTE_ADDR','')

        # Validate username and password
        if not username or not password:
            logger.warning(f"Failed login attempt from {ip_address}: Missing username or password.")
            return Response({'error': 'Username and password are required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the username is an email or username
        if '@' in username:
            try:
                user = User.objects.get(email=username)
            except User.DoesNotExist:
                logger.warning(f"Failed login attempt for {username} from {ip_address}: User does not exist")
                return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check if the account is locked in the database
        
        if user.is_locked:
            print(f"locked account attempt by {user.username}")
            logger.warning(f"Login attempt by Locked Account by {user.username} from {ip_address}")
            return Response({'error': 'Account is locked'}, status=status.HTTP_403_FORBIDDEN)

        # Track failed login attempts in cache
        cache_key = f'login_attempts_{user.username}'
        failed_attempts = cache.get(cache_key, 0)    
        
        # Authenticate the user
        authenticated_user = authenticate(username=user.username, password=password)

        # # Ensure email is verified if required
        # if EmailAddress.objects.filter(user=user, verified=False).exists():
        #     return Response({'error': 'Email is not verified'}, status=status.HTTP_400_BAD_REQUEST)

        if authenticated_user is None:
            # Increment failed login attempts in cache
            failed_attempts += 1
            print(f'Failed attempts for user {user.username}: {failed_attempts}')
            cache.set(cache_key, failed_attempts, timeout=self.LOCKOUT_DURATION)

            # Lock the account if failed attempts exceed the threshold
            if failed_attempts >= self.MAX_FAILED_ATTEMPTS:
                user.is_locked = True
                user.save()
                logger.error(f"Account locked due to excessive failed login attempts for {user.username} from {ip_address}")
                return Response({'error': 'Too many failed attempts. Account is locked.'}, status=status.HTTP_403_FORBIDDEN)

            return Response({'error': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Reset failed login attempts on successful login
        cache.delete(cache_key)
        print('successfull login attempt cache key is reset.')
        logger.info(f"Successful login for {user.username} from {ip_address}")

        otp = str(randint(100000, 999999))

        otp_instance, created = OTP.objects.update_or_create(user=user, defaults={'otp': otp, 'created_at': timezone.now()})

        send_mail(
            'Your OTP Code',
            f'Your OTP code is {otp}. It expires in 5 minutes.',
            'from@example.com',
            [user.email],
            fail_silently=False,
        )

        return Response({'message': 'OTP sent to your email. Please verify.'}, status=status.HTTP_200_OK)


class VerifyOTPView(APIView):
    '''
    Verifies the OTP and issues JWT tokens.
    '''
    def post(self, request):
        username = request.data.get('username')
        otp = request.data.get('otp')
        ip_address = request.Meta.get('REMOTE_ADDR','')

        if not username or not otp:
            logger.warning(f"Failed attempt from {ip_address}: Missing username or otp.")
            return Response({'error': 'Username and OTP are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=username) if '@' in username else User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            otp_instance = OTP.objects.get(user=user)
        except OTP.DoesNotExist:
            return Response({'error': 'OTP not found. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        if not otp_instance.is_valid() or otp_instance.otp != otp:
            return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)

        #If OTP is valid, delete it and issue tokens
        otp_instance.delete()
        logger.info(f"Successfull Login by {user.username}: otp deleted.")
        perform_login(request, user)

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        response = Response(
            {
                'status': 'OTP verified. Login successful',
                'access': access_token,
                'refresh': str(refresh),
            },
            status=status.HTTP_200_OK
        )
        #storing refresh token in a cusotm header
        response["Refresh-Token"] = str(refresh)
        
        print(str(refresh))
        return response


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            user.save()

            ip_address = request.META.get('REMOTE_ADDR', '')

            # Logging the password change event
            UserActivity.objects.create(user=user, action="Password Changed", ip_address=ip_address)
            logger.info(f"Password changed for {user.username} from {ip_address}")

            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            # Send password reset email
            serializer.save()

            ip_address = request.META.get('REMOTE_ADDR', '')
            user = User.objects.get(email=serializer.validated_data["email"])

            UserActivity.objects.create(user=user, action="Password Reset Request Initiated.", ip_address=ip_address)
            logger.info(f"Password reset request initiated for {user.username} from {ip_address}")

            return Response({"message": "A password reset link is sent to your email."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# @method_decorator(csrf_exempt, name='dispatch')
class PasswordResetView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, uid, token):
        data = request.data.copy()  
        data.update({"uid": uid, "token": token})  
        
        serializer = PasswordResetSerializer(data=data)
        if serializer.is_valid():
            # Reset the user's password
            user = serializer.save()

            ip_address = request.META.get('REMOTE_ADDR', '')

            UserActivity.objects.create(user=user, action="Password Reset Successfully.", ip_address=ip_address)
            logger.info(f"Password reset successful for {user.username} from {ip_address}")

            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class LogoutView(APIView):
#     def post(self, request):
#          try:
#             refresh_token = request.data["refresh_token"]
#             token = RefreshToken(refresh_token)
#             token.blacklist()
            
#             return Response({'message': 'Successfully logged out.'},status=status.HTTP_200_OK)
#          except Exception as e:
#              return Response(status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        ip_address = request.META.get('REMOTE_ADDR', '')
        user = request.user
        try:
            # Get refresh token from a custom header
            refresh_token = request.headers.get('Refresh-Token')
            if not refresh_token:
                logger.warning(f"Logout attempt failed (no token) by {user.username} from {ip_address}")
                return Response({"error": "No refresh token provided"}, status=status.HTTP_400_BAD_REQUEST)

            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            logger.info(f"User {user.username} successfully logged out from {ip_address}")

            UserActivity.objects.create(user=user, action="Logged out", ip_address=ip_address)
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


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

