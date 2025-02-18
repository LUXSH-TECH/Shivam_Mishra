from django.urls import path
from accounts.views import *

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name ='api-register'),
    path('api/login/', LoginView.as_view(), name ='api-login'),
    path('api/logout/', LogoutView.as_view(), name ='api-logout'),
    path('api/change_password/', ChangePasswordView.as_view(), name='api-change-password'),
    path('api/request_reset_password/', PasswordResetRequestView.as_view(), name='api-request-reset-pasword'),
    path('api/reset_password/<uidb64>/<token>/', PasswordResetView.as_view(), name='api-reset-password'),
    #             <-----urls for templates -----> 
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('request_password_reset/', request_reset_password_view, name='request-password-reset'),
    path('reset_password/', reset_password_view, name='reset-password')
]