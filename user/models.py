from ast import Delete
from typing import Any
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
)

class UserProfileManager(BaseUserManager):
    """Manager for User Profile."""
    def create_user(self, email, name, password=None, password2=None):
        """Creating the user"""
        if not email:
            raise ValueError('User must have an email address.')

        email = self.normalize_email(email)

        # if password != password2:
        #     raise ValueError('Passwords do not match!!!')

        user = self.model(email=email, name=name)

        user.set_password(password) # convert the password to hash
        user.save(using=self._db)

        return user

    def create_superuser(self, email, name, password, password2):
        """Creating the super user."""
        user = self.create_user(email, name, password, password2)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)

        return user


class UserProfile(AbstractBaseUser, PermissionsMixin):
    """Database for the users."""
    email = models.EmailField(max_length=64 ,unique=True)
    name = models.CharField(max_length=64)
    password2 = models.CharField(max_length=64)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    otp = models.IntegerField(null=True)
    

    objects = UserProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name','password2']

    def get_full_name(self):
        """Retrieving the full name of user."""
        return self.name

    def get_short_name(self):
        """Retrieve short name of user."""
        return self.name

    def __str__(self):
        """Retrieve string represention of the user."""
        return self.email # return the item you want to identify your user.

    