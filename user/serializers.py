

from rest_framework import serializers

from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import (
    get_user_model,
    authenticate,
)

from .models import UserProfile
from .email import send_otp_via_email

from rest_framework import status, generics
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login
from rest_framework.response import Response

from django.conf import settings
from django.core.cache import cache
import random


class UserSerializer(serializers.ModelSerializer):
    """User Serializer for user view."""
    # password = serializers.CharField(write_only=True, validators=[validate_password])
    # PasswordConfirmation = serializers.CharField(write_only=True)
    class Meta:
        model = UserProfile
        fields = ['id', 'email', 'name', 'password', 'password2']
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {'input_type': 'password'},
            },
            'password2': {
                'write_only': True,
                'style': {'input_type': 'password'}
            }
        }

    def create(self, validatad_data):
        password = validatad_data.pop('password')
        password2 = validatad_data.pop('password2', None)

        if password != password2:
            raise serializers.ValidationError('Password do not match!')

        user = UserProfile.objects.create_user(
            email=validatad_data['email'],
            name=validatad_data['name']
        )

        user.set_password(password)  # Hash the password using set_password
        user.save()
        
        return user

        
    
    def update(self, instance, validated_data):
        # user = self.context['request'].user
        # instance.name = validated_data['name']
        # instance.email = validated_data['email']

        # instance.save()

        # return instance
        return super().update(instance, validated_data)



class UserLoginSerializer(serializers.ModelSerializer):
    """Serializer for getting the login information."""
    class Meta:
        model = UserProfile
        fields = ['id', 'email', 'password']
        extra_kwargs = {
                'password': {
                    'write_only': True,
                    'style': {'input_type': 'password'},
                },
        }

class ChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = UserProfile
        fields = ('old_password', 'password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError({"old_password": "Old password is not correct"})
        return value

    def update(self, instance, validated_data):
        
        instance.set_password(validated_data['password'])
        instance.save()

        return instance


class VerifyAccountgSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
