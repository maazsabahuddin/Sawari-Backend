"""Django URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from User.views import Register, IsVerified, UserLogin, UserLogout, UserResendOtp, PasswordReset, PasswordResetCheck, \
    PasswordChange, SetNewPassword
from Reservation.views import BusRoute, BookingDetails, BookRide

urlpatterns = [
    path('admin/', admin.site.urls),

    # Register User.
    path('register/', Register.as_view(), name='user_register_api'),
    path('is_verified/', IsVerified.as_view(), name='user_is_verified'),

    # User login logout API.
    path('login/', UserLogin.as_view(), name='customer_login'),
    path('logout/', UserLogout.as_view(), name='customer_logout'),

    path('display_buses/', BusRoute.as_view(), name='bus_route'),
    path('booking_details/', BookingDetails.as_view(), name='booking'),
    path('reserve_ride/', BookRide.as_view(), name='reserve_a_ride'),
    path('resend_otp/', UserResendOtp.as_view(), name='resend_otp'),

    # Reset your password
    path('password/reset/', PasswordReset.as_view(), name='password_reset'),
    path('confirm/password/reset/', PasswordResetCheck.as_view(), name='confirm_password_reset'),
    path('new/password/reset/', SetNewPassword.as_view(), name='set_new_password'),

    # Password change when login.
    path('password_change/', PasswordChange.as_view(), name='password_change'),

]
