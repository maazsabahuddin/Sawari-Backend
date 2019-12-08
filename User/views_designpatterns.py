import datetime
import re
import uuid
from abc import abstractmethod

from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.http import JsonResponse
from django_twilio.client import Client
from rest_framework import generics

from rest_framework.permissions import AllowAny
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView

from A.settings import TWILIO_AUTH_TOKEN, TWILIO_ACCOUNT_SID, OTP_INITIAL_COUNTER, EMAIL_REGEX, PHONE_NUMBER_REGEX, \
    EMAIL_VERIFICATION, PHONE_VERIFICATION
from CustomAuthentication.backend_authentication import CustomAuthenticationBackend, CustomUserCheck
from User.decorators import login_credentials, otp_verify, login_decorator, register, password_reset_decorator, \
    logout_decorator, resend_otp, phone_number_decorator
from .models import User, Customer, UserOtp
from User.context_processors import singleton
from User.otp_verify import UserOTPMixin

account_sid = TWILIO_ACCOUNT_SID
auth_token = TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)


class UserMixinMethods(object):

    # Decides which of the following concrete method will return
    @staticmethod
    def get_serializer_object_register(email, phone_number):
        if email and phone_number:
            return Register().email_phone_otp

        elif email:
            return Register().email_otp

        elif phone_number:
            return Register().phone_otp

    @staticmethod
    def validate_email(email):
        email_validation = re.search(EMAIL_REGEX, email)
        if not email_validation:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Invalid Email',
            })

    @staticmethod
    def validate_phone(phone_number):
        phone_number_validation = re.match(PHONE_NUMBER_REGEX, phone_number)
        if not phone_number_validation:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Invalid Phone Number',
            })

    @staticmethod
    def user_otp_save(user, otp):
        if user:
            otp_counter = user.otp_counter
            otp_counter += 1

            user.otp = otp
            user.otp_time = datetime.datetime.today()
            user.is_verified = False
            user.otp_counter = otp_counter
            user.save()
            return True

        return False

    @staticmethod
    def save_user_password_reset_uuid(user, password_uuid):
        if user:
            user.password_reset_id = password_uuid
            user.save()
            return True
        return False

    @staticmethod
    def match_user_password_reset_uuid(user, password_uuid):
        user_obj = UserOtp.objects.filter(user=user).first()
        if user_obj and user_obj.password_reset_id == password_uuid:
            return True
        return False


# Each distinct product of a product family should have a base interface.
class RegisterCase(generics.GenericAPIView):

    def post(self, request):
        return Register().post(request)

    @abstractmethod
    def email_phone_otp(self, otp, **kwargs):
        pass

    @abstractmethod
    def email_otp(self, otp, **kwargs):
        pass

    @abstractmethod
    def phone_otp(self, otp, **kwargs):
        pass


class ResendOtpRegister(UserMixinMethods, generics.GenericAPIView):

    @staticmethod
    def get_method_object(email, phone_number):
        try:
            if email and phone_number:
                return ResendOtpRegister().email_phone_resend_otp
            elif phone_number:
                return ResendOtpRegister().phone_resend_otp
            elif email:
                return ResendOtpRegister().email_resend_otp

        except Exception as e:
            print(str(e))

    @staticmethod
    def email_phone_resend_otp(user_otp_obj, otp, **kwargs):
        try:
            email = kwargs.get('email')
            phone_number = kwargs.get('phone_number')

            if EMAIL_VERIFICATION:
                UserOTPMixin.send_otp_email(email, otp)

            if PHONE_VERIFICATION:
                UserOTPMixin.send_otp_phone(phone_number, otp)

            UserMixinMethods.user_otp_save(user_otp_obj, otp)

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'OTP has been successfully resent.',
            })

        except Exception as e:
            print(str(e))

    @staticmethod
    def email_resend_otp(user_otp_obj, otp, **kwargs):
        try:
            email = kwargs.get('email')

            if EMAIL_VERIFICATION:
                UserOTPMixin.send_otp_email(email, otp)

            UserMixinMethods.user_otp_save(user_otp_obj, otp)

            return JsonResponse({
                'status': HTTP_200_OK,
                # 'verification': EMAIL_VERIFICATION,
                'message': 'OTP has been successfully resent.',
            })

        except Exception as e:
            print(str(e))

    @staticmethod
    def phone_resend_otp(user_otp_obj, otp, **kwargs):
        try:
            phone_number = kwargs.get('phone_number')

            if not phone_number:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'Phone number not found.',
                })

            if PHONE_VERIFICATION:
                UserOTPMixin.send_otp_phone(phone_number, otp)

            UserMixinMethods.user_otp_save(user_otp_obj, otp)
            print(otp)

            return JsonResponse({
                'status': HTTP_200_OK,
                # 'verification': PHONE_VERIFICATION,
                'message': 'OTP has been successfully resent.',
            })

        except Exception as e:
            print(str(e))

    @resend_otp
    @transaction.atomic
    def post(self, request, context=None):
        try:
            user = context['user']
            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'User not found',
                })

            user_otp_obj = UserOtp.objects.filter(user=user).first()

            with transaction.atomic():

                otp = UserOTPMixin.generate_otp()
                # FACTORY PATTERN it delegates the decision to the get_serializer method and
                # return the object of concrete/implementation method
                serializer = ResendOtpRegister.get_method_object(user.email, user.phone_number)
                return serializer(user_otp_obj, otp, email=user.email, phone_number=user.phone_number)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': "Server Error." + str(e),
            })


# @singleton
class Register(RegisterCase, UserMixinMethods):

    permission_classes = (AllowAny,)

    def email_phone_otp(self, otp, **kwargs):
        try:
            email = kwargs.get('email')
            phone_number = kwargs.get('phone_number')

            if EMAIL_VERIFICATION:
                UserOTPMixin.send_otp_email(email, otp)

            if PHONE_VERIFICATION:
                UserOTPMixin.send_otp_phone(phone_number, otp)
                return True
            return False

        except Exception as e:
            print(str(e))

    def email_otp(self, otp, **kwargs):

        try:
            email = kwargs.get('email')

            # Sending OTP Via Email
            if EMAIL_VERIFICATION:
                UserOTPMixin.send_otp_email(email, otp)
                return True
            return False

        except Exception as e:
            print(str(e))

    def phone_otp(self, otp, **kwargs):
        try:
            phone_number = kwargs.get('phone_number')

            # Sending OTP Via Phone
            if PHONE_VERIFICATION:
                UserOTPMixin.send_otp_phone(phone_number, otp)
                return True

            return False

        except Exception as e:
            print(str(e))

    @register
    @transaction.atomic
    def post(self, request, context=None):
        try:
            email = context['email']
            phone_number = context['phone_number']
            password = context['password']
            is_customer = context['is_customer']

            user_email = User.objects.filter(email=email).first()
            user_phone_no = User.objects.filter(phone_number=phone_number).first()

            if user_email or user_phone_no:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Email/Phone already registered.',
                })

            with transaction.atomic():

                otp = UserOTPMixin.generate_otp()
                print(otp)
                # FACTORY PATTERN it delegates the decision to the get_serializer method and
                # return the object of concrete/implementation method
                serializer = UserMixinMethods.get_serializer_object_register(email, phone_number)
                if not serializer(otp, email=email, phone_number=phone_number):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'OTP not sent.',
                    })

                if not email:
                    email = None
                if not phone_number:
                    phone_number = None

                user = User.objects.create(
                    email=email,
                    phone_number=phone_number,
                    password=make_password(password),
                    is_active=False,
                    is_customer=is_customer,
                )
                user_otp = UserOtp.objects.create(
                    user=user,
                    otp=otp,
                    otp_time=datetime.datetime.today(),
                    otp_counter=OTP_INITIAL_COUNTER,
                    is_verified=False,
                )
                user_otp.save()
                user.save()

                Customer.objects.create(user=user)
                if user:
                    token, _ = Token.objects.get_or_create(user=user)

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'token': token.key,
                    'message': 'OTP has been successfully sent.',
                })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class IsVerified(generics.GenericAPIView, UserOTPMixin):

    @staticmethod
    def verify_otp(user, otp):

        time_now = datetime.datetime.today()
        verify_result = UserOTPMixin.verify_user_otp(user, otp, time_now)

        if verify_result:
            user.is_active = True
            user.save()
            return True

        return False

    @otp_verify
    def post(self, request, context=None):
        try:
            user = context['user']
            otp = context['otp']

            if user.is_active:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Already Verified',
                })

            if self.verify_otp(user, otp):
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'Verified',
                })

            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'OTP not matched.',
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': str(e),
            })


# User Login - Customer
class UserLogin(generics.GenericAPIView, UserMixinMethods):

    @login_credentials
    def post(self, request, context=None):
        try:
            email_or_phone = context['email_or_phone']
            password = context['password']

            user = CustomAuthenticationBackend.authenticate(email_or_phone, password)

            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'Invalid credentials.',
                })

            if not user.is_customer:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Is customer field is false.',
                })

            token, _ = Token.objects.get_or_create(user=user)
            if not user.is_active:
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'token': token.key,
                    'message': 'User not authenticated. Please verify first.',
                })

            return JsonResponse({
                'status': HTTP_200_OK,
                'token': token.key,
                'message': 'Login Successfully',
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server down' + str(e),
            })


class UserLogout(APIView):

    @logout_decorator
    def post(self, request, **kwargs):
        try:
            token_user = kwargs.get('user')

            is_logout = token_user.user.auth_token.delete()
            if is_logout:
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'Logged out',
                })

            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': 'Unable to logout',
            })
        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Error. ' + str(e)
            })


class PasswordReset(generics.GenericAPIView, UserOTPMixin):

    @staticmethod
    def get_method_object(email, phone_number):
        try:
            if email and phone_number:
                return PasswordReset.email_phone_otp
            if email:
                return PasswordReset.email_otp
            if phone_number:
                return PasswordReset.phone_otp

        except Exception as e:
            print(str(e))

    @staticmethod
    def email_phone_otp(user_otp_obj, otp, **kwargs):
        try:
            email = kwargs.get('email')
            phone_number = kwargs.get('phone_number')
            password_uuid = kwargs.get('password_uuid')

            if EMAIL_VERIFICATION:
                UserOTPMixin.send_otp_email(email, otp)

            if PHONE_VERIFICATION:
                UserOTPMixin.send_otp_phone(phone_number, otp)

            UserMixinMethods.user_otp_save(user_otp_obj, otp)
            UserMixinMethods.save_user_password_reset_uuid(user_otp_obj, password_uuid)

            return JsonResponse({
                'status': HTTP_200_OK,
                'token_uuid': password_uuid,
                'message': 'OTP has been successfully sent.',
            })

        except Exception as e:
            print(str(e))

    @staticmethod
    def email_otp(user_otp_obj, otp, **kwargs):
        try:
            email = kwargs.get('email')
            password_uuid = kwargs.get('password_uuid')

            if EMAIL_VERIFICATION:
                UserOTPMixin.send_otp_email(email, otp)

            UserMixinMethods.user_otp_save(user_otp_obj, otp)
            UserMixinMethods.save_user_password_reset_uuid(user_otp_obj, password_uuid)

            return JsonResponse({
                'status': HTTP_200_OK,
                'token_uuid': password_uuid,
                'message': 'OTP has been successfully sent.',
            })

        except Exception as e:
            print(str(e))

    @staticmethod
    def phone_otp(user_otp_obj, otp, **kwargs):
        try:
            phone_number = kwargs.get('phone_number')
            password_uuid = kwargs.get('password_uuid')

            if PHONE_VERIFICATION:
                UserOTPMixin.send_otp_phone(phone_number, otp)

            UserMixinMethods.user_otp_save(user_otp_obj, otp)
            UserMixinMethods.save_user_password_reset_uuid(user_otp_obj, password_uuid)

            return JsonResponse({
                'status': HTTP_200_OK,
                'token_uuid': password_uuid,
                'message': 'OTP has been successfully sent.',
            })

        except Exception as e:
            print(str(e))

    @transaction.atomic
    def post(self, request):
        try:
            email_or_phone = request.data.get('email_or_phone')

            if not email_or_phone:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Email/Phone is required'
                })

            is_phone_number = re.match(PHONE_NUMBER_REGEX, email_or_phone)
            is_email = re.search(EMAIL_REGEX, email_or_phone)
            if not is_phone_number and not is_email:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid format Email/Phone',
                })

            user = CustomUserCheck.check_user(email_or_phone)
            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No such email/phone exist.',
                })

            if is_phone_number and is_email:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid format Email/Phone',
                })

            user_otp_obj = UserOtp.objects.filter(user=user).first()
            with transaction.atomic():

                otp = UserOTPMixin.generate_otp()
                password_uuid = uuid.uuid4()
                print(otp)
                # Factory method design pattern same as RegisterResend OTP
                serializer = PasswordReset.get_method_object(user.email, user.phone_number)
                return serializer(user_otp_obj, otp, email=user.email, phone_number=user.phone_number,
                                  password_uuid=password_uuid)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class PasswordResetCheck(generics.GenericAPIView):

    @password_reset_decorator
    @transaction.atomic
    def post(self, request, data=None):
        try:
            user_otp = data['user']
            otp = request.data.get('otp')

            if not otp:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'OTP required.',
                })

            with transaction.atomic():

                if IsVerified.verify_otp(user_otp.user, otp):
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'message': 'Verified',
                    })

                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'OTP not matched.',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server Error.' + str(e),
            })


class SetNewPassword(generics.GenericAPIView):

    @password_reset_decorator
    @transaction.atomic
    def post(self, request, data=None):
        try:
            user_otp = data['user']
            password = request.data.get('pin1')
            confirm_password = request.data.get('pin2')

            if not (password or confirm_password):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Password field required.',
                })

            if password != confirm_password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Password Fields not matched.',
                })

            with transaction.atomic():

                # Moving into UserOtp model then access the field user and then move to Auth user and get the password.
                # So user.user.password.
                if password == user_otp.user.password:
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'You cannot set old password as new password.',
                    })

                user_otp.user.set_password(password)
                user_otp.user.is_active = True
                user_otp.user.save()

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': "Password has been successfully reset.",
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': "Server Error.",
            })


class PasswordResetResendOtp(generics.GenericAPIView, UserOTPMixin):

    @password_reset_decorator
    @transaction.atomic
    def post(self, request, data=None):
        try:
            user_otp = data['user']

            with transaction.atomic():

                otp = UserOTPMixin.generate_otp()
                # FACTORY PATTERN it delegates the decision to the get_serializer method and
                # return the object of concrete/implementation method
                serializer = ResendOtpRegister.get_method_object(user_otp.user.email, user_otp.user.phone_number)
                return serializer(user_otp, otp, email=user_otp.user.email, phone_number=user_otp.user.phone_number)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': "Server Error. " + str(e),
            })


class UpdateName(generics.GenericAPIView):

    @transaction.atomic
    @login_decorator
    def post(self, request, data=None):
        try:
            user = data['user']
            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': "User not found.",
                })

            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name')

            if not first_name:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'First Name is required.',
                })

            with transaction.atomic():
                user.first_name = first_name
                user.last_name = last_name
                user.save()

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': "Your name successfully updated.",
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


# Pending
class ChangePhoneNumber(generics.GenericAPIView, UserOTPMixin):

    @transaction.atomic
    @login_decorator
    @phone_number_decorator
    def post(self, request, **kwargs):
        try:
            user = kwargs.get('user')
            phone_number = kwargs.get('phonenumber')

            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "User not found."
                })

            with transaction.atomic():
                otp = UserOTPMixin.generate_otp()
                user_otp_obj = UserOtp.objects.filter(user=user).first()
                if not user_otp_obj:
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': "User not found."
                    })
                ResendOtpRegister.phone_resend_otp(user_otp_obj, otp, phone_number=phone_number)

                print(otp)
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'OTP has been successfully sent.',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server Error.' + str(e),
            })


class ChangePhoneNumberOtpMatch(generics.GenericAPIView):

    @transaction.atomic
    @otp_verify
    def post(self, request, data=None):

        user = data['user']
        otp = data['otp']
        phone_number = request.data.get('phone_number')

        if not phone_number:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': 'Phone number required',
            })

        verified = IsVerified.verify_otp(user, otp)

        if not verified:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'OTP not matched.',
            })

        user.phone_number = phone_number
        user.save()

        return JsonResponse({
            'status': HTTP_400_BAD_REQUEST,
            'message': 'Phone Number successfully changed.',
        })


class PasswordChange(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data=None):
        try:
            user = data['user']
            previous_pin = request.data.get('previous_pin')
            new_pin = request.data.get('new_pin')
            confirm_new_pin = request.data.get('confirm_new_pin')

            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No user found',
                })

            if not (previous_pin and new_pin and confirm_new_pin):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Previous pin / new pin and confirm pin are required.',
                })

            if new_pin != confirm_new_pin:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Password Fields not matched.',
                })

            if new_pin == previous_pin:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'You cannot set old pin as new pin.',
                })

            if not user.check_password(previous_pin):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Previous Pin not matched.',
                })

            user.set_password(new_pin)
            user.save()

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'Password has been changed.',
            })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class UserDetails(generics.GenericAPIView):

    @login_decorator
    def get(self, request, data=None):
        try:
            user = data['user']
            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'messgae': 'User not found.',
                })

            if not user.email:
                user.email = ""

            if not user.phone_number:
                user.phone_number = ""

            return JsonResponse({
                'status': HTTP_200_OK,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'phone_number': user.phone_number,
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })
