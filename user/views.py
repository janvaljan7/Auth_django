
from functools import partial
from requests import session
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework.authtoken.models import Token
from rest_framework.request import Request
from rest_framework.renderers import JSONRenderer
from rest_framework.settings import api_settings


from django.contrib.auth import authenticate, login
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from yaml import serialize

from user.email import send_otp_via_email

from .serializers import UserSerializer, UserLoginSerializer, ChangePasswordSerializer, VerifyAccountgSerializer
from .models import UserProfile
from user.permissions import UpdateOwnProfile

from django.contrib.auth import get_user_model
# import requests
class CreateUser(APIView):
    """The user API view."""
    serializer_class = UserSerializer
    # authentication_classes = [TokenAuthentication]
    # permission_classes = [UpdateOwnProfile]
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request):
        """Create a user."""
        serializer = self.serializer_class(data=request.data)

        # if  serializer.is_valid():
        #     email = serializer.validated_data['email']
        #     password = serializer.validated_data['password']
        #     user = serializer.save()

        #     user = authenticate(request, username=email, password=password)
        #     if user:
        #         login(request, user)
        #         token, _ = Token.objects.get_or_create(user=user)

        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            serializer.save()

            # Authenticate the user
            User = get_user_model()
            authenticated_user = User.objects.get(email=email)
            authenticated_user.set_password(password)
            authenticated_user.save()

            # Log in the user
            login(request, authenticated_user)

            # Generate and return the authentication token
            token, _ = Token.objects.get_or_create(user=authenticated_user)


            #     return Response({"token": token.key, "message": "User logged in."})
            # else:
            #     return Response({"error": "Invalid username/password."})
            
            send_otp_via_email(serializer.data['email'])
            return Response({'Message': 'User created, check your email.', 'token': token.key}, status=status.HTTP_201_CREATED)
        else:
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
    

class UpdateUser(APIView):
    """The user API view."""
    serializer_class = UserSerializer
    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def patch(self, request, pk):
        """Update the whole data of a user."""
        
        try: 
            user = request.user 
            serializer = UserSerializer(instance=user, data=request.data, partial=True)
            if serializer.is_valid():
                user = serializer.save()
                # user = authenticate(request, username=user.email, password=request.data.get('password'))
                # if user: 
                #     login(request, user)
                return Response({'message': 'User updated successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from rest_framework.authentication import SessionAuthentication
class DeleteUser(APIView):
    """The user API view."""
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [UpdateOwnProfile]
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def delete(self, request, pk):
        """Delete the user."""
        print("pk:", pk)
        print("request.user.id:", request.user.pk)
        try:
            user = UserProfile.objects.get(pk=pk)
            if pk != request.user.pk:
                return Response({'Message': 'Not authorized!'}, status=status.HTTP_401_UNAUTHORIZED)
        except UserProfile.DoesNotExist:
            return Response({'Message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

        user.delete()
        return Response({'Message': 'User deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)


class LoginAPIView(APIView):
    authentication_classes = [TokenAuthentication]
    serializer_class = UserLoginSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request):
        if request.user.is_authenticated:
            return Response({"message": "User is already logged in."})
        email = request.data.get('email')
        password = request.data.get('password')
        # user.set_password(password)
        user = authenticate(request, username=email, password=password)
        if user:
            token, _ = Token.objects.get_or_create(user=user)
            login(request, user)
            return Response({"token": token.key, "message": "User logged in."})
        else:
            return Response({"error": "Invalid username/password."})

class UserProfileListView(generics.ListAPIView):
    """Create a list of the Users to view."""
    queryset = UserProfile.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

class ChangePasswordView(generics.UpdateAPIView):
    """Changing the password."""
    queryset = UserProfile.objects.all()
    permission_classes = [IsAuthenticated, UpdateOwnProfile]
    serializer_class = ChangePasswordSerializer

    def put(self, request, pk):
        try:
            user = UserProfile.objects.get(pk=pk)
            if user != request.user:
                return Response({'Message': 'Not authorized!'}, status=status.HTTP_401_UNAUTHORIZED)
        except UserProfile.DoesNotExist:
            return Response({'message': 'User profile not found'}, status=404)

        serializer = ChangePasswordSerializer(user, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Password changed successfully'})
        
        return Response(serializer.errors, status=400)

class VerifyEmailAPIView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, UpdateOwnProfile]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        otp_from_cache = cache.get(email)
        if otp == otp_from_cache:
            user = UserProfile.objects.get(email=email)
            user.is_active = True
            user.save()
            return Response({"message": "OTP matched and user activated."})
        else:
            return Response({"error": "OTP did not match."})    
        

class VerifyOTP(APIView):
    authentication_classes = [SessionAuthentication]
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request):
        try:
            serializer = VerifyAccountgSerializer(data=request.data, context={'request': request})

            if serializer.is_valid():
                email = serializer.data['email']
                print(email)
                otp = cache.get(email)
                print(otp)
                user = UserProfile.objects.filter(email=email)
                print(user)
                authenticated_user = request.user
                print(authenticated_user)
                if user.exists() and user[0] == authenticated_user:
                    if user[0].otp == otp:
                        user[0].is_verified = True
                        user[0].save()

                        return Response({
                            'status': 200,
                            'message': 'Account verified!',
                            'data': serializer.data
                        })
                    else:
                        return Response({
                            'status': 400,
                            'message': 'Invalid OTP!',
                            'data': 'Invalid email or OTP'
                        })
                else:
                    return Response({'Message': 'OTP is not correct or expired!'}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({
                'status': 400,
                'message': 'Invalid data.',
                'data': serializer.errors
            })

        except Exception as e:
            return Response({
                'status': 500,
                'message': 'An error occurred.',
                'data': str(e)
            })
        
from django.http import JsonResponse

class user_retrieve(APIView):
    """Retriving the user."""
    def get(self, request): 
        user_data = {
                'email': request.user.email,
                'id': request.user.id
            }
        return JsonResponse({'user': user_data})