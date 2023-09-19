from turtle import update
from . import views
from django.urls import path



urlpatterns = [
    path('create/', views.CreateUser.as_view(), name='Create_User'),
    path('update/<int:pk>/', views.UpdateUser.as_view(), name='Update_User'),
    path('delete/<int:pk>/', views.DeleteUser.as_view(), name='Delete_User'),
    path('login/', views.LoginAPIView.as_view(), name='user_login'),
    path('list/', views.UserProfileListView.as_view(), name='user_list'),
    path('changepass/<int:pk>/', views.ChangePasswordView.as_view(), name='user_change_password'),
    path('verify/', views.VerifyOTP.as_view(), name='verify_email'),
    path('user/', views.user_retrieve.as_view(), name='user_retrieve'),
]
