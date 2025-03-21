from rest_framework import serializers
from accounts.models import *
from django.contrib.auth import authenticate
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from accounts.helper import custom_password_validator


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'full_name', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user =User(
            username=validated_data['username'],
            email=validated_data['email'],
            full_name=validated_data['full_name']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user        
    

class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password']


class CreateUserSerializer(serializers.ModelSerializer):
        is_active = serializers.BooleanField(default=True)
        is_inactive = serializers.BooleanField(default=False)
        is_locked = serializers.BooleanField(default=False)

        class Meta:
            model = User
            fields = ['username', 'email', 'password', 'full_name', 'is_active','is_admin', 'is_inactive', 'is_locked']
            read_only_fields = ['created_at', 'updated_at']
            extra_kwargs = {'password': {'write_only': True}}

        def create(self, validated_data):
            user = User(
                username=validated_data['username'],
                email=validated_data['email'],
                full_name=validated_data['full_name'],
                is_active=validated_data['is_active'],
                is_inactive=validated_data['is_inactive'],
                is_locked=validated_data['is_locked'],
            )

            user.set_password(validated_data['password'])
            user.save()
            return user 


class UserSerializer(serializers.ModelSerializer):
     class Meta:
          model = User
          fields = ['id', 'username', 'email', 'full_name', 'is_active', 'is_inactive', 'is_locked', 'created_at', 'updated_at', 'is_mfa_enabled']


class ChangePasswordSerializer(serializers.Serializer):
        password = serializers.CharField( required=True, validators=[custom_password_validator])
        confirm_password = serializers.CharField(required=True)

        class Meta:
             fields = ['password', 'confirm_password']

        def validate(self, attrs):
             password = attrs.get('password')
             confirm_password = attrs.get('confirm_password')
    
             if password != confirm_password:
                  raise serializers.ValidationError('passwords do not match')
            
             return attrs
             
        def save(self):
             user = self.context.get('user')
             user.set_password(self.validated_data['password'])
             user.save()


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, data):
        try:
            self.user = User.objects.get(email=data)
        except User.DoesNotExist:
            raise serializers.ValidationError("No user found with this email address.")
        return data

    def save(self):
        user = self.user
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        reset_link = f"http://127.0.0.1:5000/accounts/reset_password/?uid={uid}&token={token}"

        # Send email
        send_mail(
            'Password Reset Request',
            f'Click the link to reset your password: {reset_link}',
            'from@example.com',
            [user.email],
            fail_silently=False,
        )


class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(required=True, validators=[custom_password_validator])
    uid = serializers.CharField(write_only=True, required=True)
    token = serializers.CharField(write_only=True, required=True)

    def validate(self, data):
        uid = data.get('uid')
        token = data.get('token')

        if not uid or not token:
            raise serializers.ValidationError("Invalid reset link data.")

        try:
            uid = urlsafe_base64_decode(uid).decode()
            print(f"Decoded UID: {uid}")  # Debugging

            user = User.objects.get(id=uid)
        except User.DoesNotExist:
        # except (TypeError, ValueError, OverflowError, User.DoesNotExist) as e:
            print(f"Error retrieving user")  # Debugging
            raise serializers.ValidationError("Invalid reset link.")

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Invalid or expired token.")
         
        data['user'] = user
        return data

    def save(self):
        user = self.validated_data['user']
        password = self.validated_data['password']

        # Set the new password
        user.set_password(password)
        user.save()
        return user