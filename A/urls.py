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
from django.conf.urls import url
from django.contrib import admin
from django.urls import path, include, re_path
from django.contrib.auth import views as auth_views
# from User.views import ResendOtpRegister, PasswordReset, PasswordResetCheck, \
#     PasswordChange, SetNewPassword, ChangePhoneNumber
from Reservation.views import UserRides, CancelRide, BookRide
from User.passwordreset import ForgotPassword
from User.views import PasswordResetLink, PasswordResetComplete, HomePage
from User.views_designpatterns import RegisterCase, UserLogin, UserLogout, ResendOtpRegister, \
    PasswordChange, ChangePhoneNumber, \
    ChangePhoneNumberOtpMatch, UpdateName, UserDetails, PasswordCheck, DeleteUser, PasswordChangeResendOtp, \
    UpdateEmail, AddUserPlace, UpdateUserPlace, UserPlaces, LoginViaGoogle, CheckUser, VerifyUser, DeleteUserPlace
from RideSchedule.views import VehicleRoute, BusRoute, CalculateFare

# from Reservation.views import BusRoute, BookingDetails, BookRide

urlpatterns = [
    path('admin/', admin.site.urls),

    # Register User.
    # path('register/', Register.as_view(), name='user_register_api'),
    path('register/', RegisterCase.as_view(), name='user_register_api'),
    path('verify/user/', VerifyUser.as_view(), name='user_is_verified'),
    path('register/resend_otp/', ResendOtpRegister.as_view(), name='resend_otp'),

    # User login logout API.
    path('check/user/', CheckUser.as_view(), name='check_user'),
    path('login/', UserLogin.as_view(), name='customer_login'),
    path('login/via/google/', LoginViaGoogle.as_view(), name='login_or_register_via_google'),
    path('logout/', UserLogout.as_view(), name='customer_logout'),

    path('bus/route/', BusRoute.as_view(), name='bus_route'),
    # path('display_buses/', VehicleRoute.as_view(), name='bus_route'),
    # path('book_ride/', RideBook.as_view(), name='reserve_a_ride'),
    # path('confirm_ride/', ConfirmRide.as_view(), name='reserve_ride'),
    path('cancel_ride/', CancelRide.as_view(), name='cancel_ride'),

    path('calculate/fare/', CalculateFare.as_view(), name='calculate_fare'),
    path('confirm/book/ride/', BookRide.as_view(), name='book_a_ride'),

    # django rest framework password reset view
    # url('^', include('django.contrib.auth.urls')),
    # path('password-reset/', auth_views.PasswordResetView.as_view(template_name='users/password_reset.html'),
    #      name='password_reset'),
    # path('password-reset-confirm/<uidb64>/<token>/',
    #      auth_views.PasswordResetConfirmView.as_view(template_name='users/password_reset_confirm.html'),
    #      name='password_reset_confirm'),
    # path('password-reset/done/',
    #      auth_views.PasswordResetDoneView.as_view(template_name='users/password_reset_done.html'),
    #      name='password_reset_done'),
    # path('password-reset-complete/',
    #      auth_views.PasswordResetCompleteView.as_view(template_name='users/password_reset_complete.html'),

    # # Reset your password
    # path('password/reset/', PasswordReset.as_view(), name='password_reset'),
    # path('password/reset/resend_otp/', PasswordResetResendOtp.as_view(), name='password_reset_resend_otp'),
    # path('confirm/password/reset/', PasswordResetCheck.as_view(), name='confirm_password_reset'),
    # path('new/password/reset/', SetNewPassword.as_view(), name='set_new_password'),

    # Password change when login.
    path('password/change/', PasswordChange.as_view(), name='password_change'),
    path('password/check/', PasswordCheck.as_view(), name='password_check'),

    # Update user phone number.
    path('change/phonenumber/', ChangePhoneNumber.as_view(), name='change_phone_number'),
    path('verify/phonenumber/', ChangePhoneNumberOtpMatch.as_view(), name='change_phone_number_verify'),
    path('phonenumber/change/resend_otp/', PasswordChangeResendOtp.as_view(), name='presend_otp'),

    # Return User Details
    path('user/rides/', UserRides.as_view(), name='user_rides'),
    path('user/details/', UserDetails.as_view(), name='user_details'),
    path('user/places/', UserPlaces.as_view(), name='user_details'),

    # Save User Place
    path('add/user/place/', AddUserPlace.as_view(), name='user_place'),
    path('update/user/place/', UpdateUserPlace.as_view(), name='user_place'),
    path('delete/user/place/', DeleteUserPlace.as_view(), name='delete_user_place'),

    # Delete User
    path('delete/user/', DeleteUser.as_view(), name='delete_user'),

    # Update User
    path('update/email/', UpdateEmail.as_view(), name='update_email'),
    path('update/name/', UpdateName.as_view(), name='update_name'),

    # Password Reset
    path('forgot/password/', ForgotPassword.as_view(), name='forgot_password'),
    path('password/reset/', PasswordResetLink, name='password_reset_form'),
    path('password/reset/done/', PasswordResetComplete, name='password_reset_done'),

    path('', HomePage, name='index'),
    re_path(r'^.*$', HomePage, name='index'),
]
