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
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView

from A.settings.base import TWILIO_AUTH_TOKEN, TWILIO_ACCOUNT_SID, OTP_INITIAL_COUNTER, EMAIL_REGEX, PHONE_NUMBER_REGEX, \
    EMAIL_VERIFICATION, PHONE_VERIFICATION
from CustomAuthentication.backend_authentication import CustomAuthenticationBackend, CustomUserCheck
from User.decorators import login_credentials, otp_verify, login_decorator, register, password_reset_decorator, \
    logout_decorator, resend_otp, phone_number_decorator, password_change_decorator, resend_otp_change_phone_number, \
    change_phone_number_otp_verify, register_via_google_decorator
from .models import User, Customer, UserOtp, Place, PlaceDetail
from User.otp_verify import UserOTPMixin

from User.exceptions import TwilioEmailException, UserException, InvalidUsage, WrongPassword, \
     UserNotAuthorized, UserNotActive

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
            return False
        return True

    @staticmethod
    def validate_phone(phone_number):
        phone_number_validation = re.match(PHONE_NUMBER_REGEX, phone_number)
        if not phone_number_validation:
            return False
        return True

    @staticmethod
    def user_otp_save(user, otp):
        try:
            if user:
                otp_counter = user.otp_counter
                otp_counter += 1

                user.otp = otp
                user.otp_time = datetime.datetime.today()
                user.is_verified = False
                user.otp_counter = otp_counter
                user.save()

        except Exception as e:
            raise UserException(status_code=404, message="User doesn't exist.")

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
        pass
        # try:
        #     if email and phone_number:
        #         return ResendOtpRegister().email_phone_resend_otp
        #     elif phone_number:
        #         return ResendOtpRegister().phone_resend_otp
        #     elif email:
        #         return ResendOtpRegister().email_resend_otp
        #
        # except InvalidUsage as e:
        #     raise InvalidUsage(status_code=100)

    @staticmethod
    def email_phone_resend_otp(otp, **kwargs):
        pass
        # phone_number = ''
        # try:
        #     email = kwargs.get('email')
        #     phone_number = kwargs.get('phone_number')
        #
        #     if EMAIL_VERIFICATION:
        #         UserOTPMixin.send_otp_email(email, otp)
        #     if PHONE_VERIFICATION:
        #         UserOTPMixin.send_otp_phone(phone_number, otp)
        #
        # except TwilioEmailException as e:
        #     if e.status_code == 102:
        #         raise TwilioEmailException(status_code=102, message="Email not sent.")
        #     if e.status_code == 101:
        #         raise TwilioEmailException(status_code=101,
        #                                    message=phone_number + " is not verified on your Twilio trial account.")

    @staticmethod
    def email_resend_otp(otp, **kwargs):
        pass
        # try:
        #     email = kwargs.get('email')
        #
        #     if EMAIL_VERIFICATION:
        #         UserOTPMixin.send_otp_email(email, otp)
        #
        # except TwilioEmailException as e:
        #     if e.status_code == 102:
        #         raise TwilioEmailException(status_code=102, message="Email not sent.")

    @staticmethod
    @transaction.atomic
    def phone_resend_otp(otp, **kwargs):
        pass
        # phone_number = ''
        # try:
        #     phone_number = kwargs.get('phone_number')
        #
        #     with transaction.atomic():
        #         if PHONE_VERIFICATION:
        #             UserOTPMixin.send_otp_phone(phone_number, otp)
        #
        # except TwilioEmailException as e:
        #     if e.status_code == 101:
        #         raise TwilioEmailException(status_code=101,
        #                                    message=phone_number + " is not verified on your Twilio trial account.")

    @transaction.atomic
    @resend_otp
    def post(self, request, data=None):
        try:
            user = data.get('user')

            user_otp_obj = UserOtp.objects.filter(user=user).first()
            with transaction.atomic():

                otp = UserOTPMixin.generate_otp()
                UserMixinMethods.user_otp_save(user_otp_obj, otp)
                # FACTORY PATTERN it delegates the decision to the get_serializer method and
                # return the object of concrete/implementation method
                serializer = UserMixinMethods.get_serializer_object_register(user.email, user.phone_number)
                serializer(otp, email=user.email, phone_number=user.phone_number)

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'OTP has been successfully resent.',
                })

        except InvalidUsage as e:
            if e.status_code == 100:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })

        except UserException as e:
            if e.status_code == 404:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })

        except TwilioEmailException as e:
            if e.status_code == 101:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })
            if e.status_code == 101:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': "Server Error. " + str(e),
            })


class RegisterViaGoogle(generics.GenericAPIView):

    @register_via_google_decorator
    def post(self, request, data=None):
        try:
            email = data.get('email')
            password = data.get('password')
            is_customer = data.get('is_customer')
            is_captain = data.get('is_captain')
            first_name = data.get('first_name')

            with transaction.atomic():
                user = User.objects.create(
                    first_name=first_name,
                    email=email,
                    password=password,
                    is_active=True,
                    is_customer=is_customer,
                )
                user.save()

                if is_customer:
                    Customer.objects.create(user=user)
                    if user:
                        token, _ = Token.objects.get_or_create(user=user)

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'token': token.key,
                    'message': 'User Registered successfully.',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Slow internet connection.',
            })


# @singleton
class Register(RegisterCase, UserMixinMethods):

    permission_classes = (AllowAny,)

    def email_phone_otp(self, otp, **kwargs):
        phone_number = ''
        try:
            email = kwargs.get('email')
            phone_number = kwargs.get('phone_number')

            if EMAIL_VERIFICATION:
                UserOTPMixin.send_otp_email(email, otp)

            if PHONE_VERIFICATION:
                UserOTPMixin.send_otp_phone(phone_number, otp)

        except TwilioEmailException as e:
            if e.status_code == 102:
                raise TwilioEmailException(status_code=102, message="Email not sent.")
            if e.status_code == 101:
                raise TwilioEmailException(status_code=101,
                                           message=phone_number + " is not verified on your Twilio trial account.")

    def email_otp(self, otp, **kwargs):
        try:
            email = kwargs.get('email')

            # Sending OTP Via Email
            if EMAIL_VERIFICATION:
                UserOTPMixin.send_otp_email(email, otp)

        except TwilioEmailException as e:
            if e.status_code == 102:
                raise TwilioEmailException(status_code=102, message="Email not sent.")

    def phone_otp(self, otp, **kwargs):
        phone_number = ''
        try:
            phone_number = kwargs.get('phone_number')

            # Sending OTP Via Phone
            if PHONE_VERIFICATION:
                UserOTPMixin.send_otp_phone(phone_number, otp)
                return True

        except TwilioEmailException as e:
            if e.status_code == 101:
                raise TwilioEmailException(status_code=101,
                                           message=phone_number + " is not verified on your Twilio trial account.")

    @transaction.atomic
    @register
    def post(self, request, data=None):
        try:
            email = data.get('email')
            phone_number = data.get('phone_number')
            password = data.get('password')
            is_customer = data.get('is_customer')
            first_name = data.get('first_name')

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
                serializer(otp, email=email, phone_number=phone_number)

                if not email:
                    email = None

                user = User.objects.create(
                    first_name=first_name,
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

        except TwilioEmailException as e:
            if e.status_code == 101:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })
            if e.status_code == 101:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class IsVerified(generics.GenericAPIView, UserOTPMixin):

    @staticmethod
    def verify_otp(user, otp):
        try:
            time_now = datetime.datetime.today()
            verify_result = UserOTPMixin.verify_user_otp(user, otp, time_now)

            if verify_result:
                user.is_active = True
                user.save()
                return True
            return False

        except UserException as e:
            if e.status_code == 405:
                raise UserException(status_code=405, message="User Counter Exception.")

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

        except UserException as e:
            if e.status_code == 405:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': str(e.message),
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': str(e),
            })


class LoginViaGoogle(generics.GenericAPIView):

    def post(self, request, data=None):
        try:
            email = request.data.get('email')
            name = request.data.get('name')
            app = request.data.get('app')

            email = email.strip()
            name = name.strip()
            if not (email and name and app):
                raise UserException(status_code=400, message="Missing values")

            user = CustomUserCheck.check_user(email)
            if app == "Customer" and not user.is_customer:
                raise UserNotAuthorized(message='Not authorized to login in the app.')

            token, _ = Token.objects.get_or_create(user=user)
            if not user.is_active and user.first_name != name:
                raise UserNotActive(message="User not authenticated. Please verify first.")

            return JsonResponse({
                'status': HTTP_200_OK,
                'token': token.key,
                'message': 'Login Successfully',
            })

        except UserNotAuthorized as e:
            return JsonResponse({
                'status': HTTP_401_UNAUTHORIZED,
                'message': str(e.message),
            })

        except UserNotActive as e:
            return JsonResponse({
                'status': HTTP_401_UNAUTHORIZED,
                'message': str(e.message),
            })

        except UserException as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Error: ' + str(e),
            })


# User Login - Customer
class UserLogin(generics.GenericAPIView, UserMixinMethods):

    @login_credentials
    def post(self, request, data=None):
        token = ''
        user = ''
        try:
            email_or_phone = data.get('email_or_phone')
            password = data.get('password')
            app = data.get('app')

            # Check if user exist or not.
            user_check = CustomUserCheck.check_user(email_or_phone)
            if not user_check:
                raise WrongPassword(message="The sign-in credentials does not exist. Try again or create a new account")
            if app == "Customer" and not user_check.is_customer:
                raise UserNotAuthorized(message='Not authorized to login in the app.')

            user = CustomAuthenticationBackend.authenticate(email_or_phone, password)
            if not user:
                raise WrongPassword(message="Invalid Credentials.")
            token, _ = Token.objects.get_or_create(user=user)
            if not user.is_active:
                raise UserNotActive(message="User not authenticated. Please verify first.")

            return JsonResponse({
                'status': HTTP_200_OK,
                'token': token.key,
                'message': 'Login Successfully',
            })

        except WrongPassword as e:
            return JsonResponse({
                'status': HTTP_401_UNAUTHORIZED,
                'message': str(e.message),
            })

        except UserNotAuthorized as e:
            return JsonResponse({
                'status': HTTP_401_UNAUTHORIZED,
                'message': str(e.message),
            })

        except UserNotActive as e:
            try:
                otp = UserOTPMixin.generate_otp()
                print(otp)
                # FACTORY PATTERN it delegates the decision to the get_serializer method and
                # return the object of concrete/implementation method
                serializer = UserMixinMethods.get_serializer_object_register(user.email, user.phone_number)
                serializer(otp, email=user.email, phone_number=user.phone_number)
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'token': token.key,
                    'message1': "OTP has been successfully sent.",
                    'message': str(e.message),
                })
            except Exception as e:
                raise TwilioEmailException(message=user.phone_number + " is not verified on your Twilio trial account.")

        except TwilioEmailException as e:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': str(e.message),
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Error: ' + str(e),
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

    @transaction.atomic
    @password_reset_decorator
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

    @staticmethod
    def has_numbers(name):
        return any(char.isdigit() for char in name)

    @staticmethod
    def check_string_for_numbers(**kwargs):
        first_name = kwargs.get('first_name')
        last_name = kwargs.get('last_name')

        name = first_name + ' ' + last_name
        return any(char.isdigit() for char in name)

    @transaction.atomic
    @login_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')

            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name')

            if not (first_name or last_name):
                raise UserException(status_code=404)

            if not first_name:
                first_name = user.first_name

            if not last_name:
                last_name = user.last_name

            if UpdateName.check_string_for_numbers(first_name=first_name, last_name=last_name):
                raise UserException(status_code=400)

            with transaction.atomic():
                user.first_name = first_name
                user.last_name = last_name
                user.save()

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'message': "Your name successfully updated.",
                })

        except UserException as e:
            if e.status_code == 404:
                return JsonResponse({
                    'status': e.status_code,
                    'message': 'Field cannot be empty.',
                })
            if e.status_code == 400:
                return JsonResponse({
                    'status': e.status_code,
                    'message': 'Name cannot contain digits.',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class ChangePhoneNumber(generics.GenericAPIView, UserOTPMixin):

    @staticmethod
    @transaction.atomic
    def phone_send_otp(user_otp_obj, otp, **kwargs):
        try:
            pass
            # phone_number = kwargs.get('phone_number')
            # user_otp_obj = kwargs.get('user_otp_obj')
            # otp = kwargs.get('otp')
            #
            # if not phone_number:
            #     return JsonResponse({
            #         'status': HTTP_404_NOT_FOUND,
            #         'message': 'Phone number not found.',
            #     })
            #
            # with transaction.atomic():
            #     if PHONE_VERIFICATION:
            #         if not UserOTPMixin.send_otp_phone(phone_number, otp):
            #             return False
            #
            #     UserMixinMethods.user_otp_save(user_otp_obj, otp)
            #     print(otp)
            #     return True

        except Exception as e:
            print(str(e))

    @transaction.atomic
    @login_decorator
    @phone_number_decorator
    def post(self, request, **kwargs):
        try:
            user = kwargs.get('user')
            phone_number = kwargs.get('phonenumber')

            with transaction.atomic():
                if PHONE_VERIFICATION:
                    otp = UserOTPMixin.generate_otp()
                    print(otp)

                    # Is current user ki saari cheezen new number waly user pr transfer hungy..
                    user_otp_obj = UserOtp.objects.filter(user=user).first()
                    UserMixinMethods.user_otp_save(user_otp_obj, otp)

                    if Register().phone_otp(otp, phone_number=phone_number):
                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'message': 'OTP has been successfully sent.',
                        })

                else:
                    user.phone_number = phone_number
                    user.save()
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'message': 'Phone Number changed.',
                    })

        except UserException as e:
            if e.status_code == 404:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "User not found.",
                })

        except TwilioEmailException as e:
            if e.status_code == 101:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server Error.' + str(e),
            })


class ChangePhoneNumberOtpMatch(generics.GenericAPIView):

    @transaction.atomic
    @login_decorator
    @change_phone_number_otp_verify
    def post(self, request, data=None):
        try:
            user = data.get('user')
            otp = data.get('otp')
            phone_number = data.get('phone_number')

            if not IsVerified.verify_otp(user, otp):
                raise InvalidUsage(status_code=401, message="OTP not matched.")

            user.phone_number = phone_number
            user.save()

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'Phone Number successfully changed.',
            })

        except InvalidUsage as e:
            if e.status_code == 401:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class PasswordChange(generics.GenericAPIView):

    @login_decorator
    @password_change_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')
            # previous_pin = data.get('previous_pin')
            new_pin = data.get('new_pin')

            user.set_password(new_pin)
            user.save()

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'Password has been changed.',
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class PasswordCheck(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')
            password = request.data.get('password')

            if not user.check_password(password):
                raise UserException(status_code=401)

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'Password Verified.',
            })

        except UserException as e:
            return JsonResponse({
                'status': 401,
                'message': 'Invalid password.',
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class UserDetails(generics.GenericAPIView):

    @login_decorator
    def get(self, request, data=None):
        try:
            user = data.get('user')
            if not user:
                raise UserException(status_code=404)

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

        except UserException as e:
            if e.status_code == 404:
                return JsonResponse({
                    'status': e.status_code,
                    'message': 'User not found.',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class DeleteUser(generics.GenericAPIView):

    @login_decorator
    def get(self, request, data=None):
        try:
            user = data.get('user')
            if not user:
                raise UserException(status_code=404)

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'User account successfully deleted.',
            })

        except UserException as e:
            if e.status_code == 404:
                return JsonResponse({
                    'status': e.status_code,
                    'message': 'User not found.',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class PasswordChangeResendOtp(generics.GenericAPIView):

    @transaction.atomic
    @login_decorator
    @resend_otp_change_phone_number
    def post(self, request, data=None):
        try:
            user = data.get('user')
            phone_number = data.get('phone_number')

            user_otp_obj = UserOtp.objects.filter(user=user).first()
            with transaction.atomic():

                otp = UserOTPMixin.generate_otp()
                UserMixinMethods.user_otp_save(user_otp_obj, otp)
                Register().phone_otp(otp, phone_number=phone_number)

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'OTP has been successfully resent.',
                })

        except InvalidUsage as e:
            if e.status_code == 100:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })

        except UserException as e:
            if e.status_code == 404:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })

        except TwilioEmailException as e:
            if e.status_code == 101:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })
            if e.status_code == 101:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': str(e.message),
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': "Server Error. " + str(e),
            })


class UpdateEmail(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data=None):
        user = data.get('user')
        email = request.data.get('email')

        if not email:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': "Email value missing."
            })

        if user.email == email:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': email + " already set to your account."
            })

        if not UserMixinMethods.validate_email(email):
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Invalid Email.',
            })

        with transaction.atomic():
            user.email = email
            user.save()

        return JsonResponse({
            'status': HTTP_200_OK,
            'message': "Email updated successfully."
        })


class AddUserPlace(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')
            place_id = request.data.get('place_id')
            place_name = request.data.get('place_name')
            latitude = request.data.get('latitude')
            longitude = request.data.get('longitude')
            place_type = request.data.get('place_type')

            if not (place_id and latitude and longitude and place_name and place_type):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "Value missing."
                })

            user_place_type_obj = Place.objects.filter(user=user.id, place_type=place_type).first()
            if user_place_type_obj and user_place_type_obj.place_type != "Other":
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "{} Place already saved.".format(user_place_type_obj.place_type)
                })

            place_detail = PlaceDetail.objects.filter(place_id=place_id).first()
            if not place_detail:
                place_detail = PlaceDetail.objects.create(
                    place_id=place_id,
                    place_name=place_name,
                    latitude=latitude,
                    longitude=longitude,
                )
                place_detail.save()

            user_place = Place.objects.filter(user=user.id, place_id=place_detail.id, place_type=place_type).first()
            if user_place:
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': "Place already saved."
                })

            with transaction.atomic():
                user_place_obj = Place.objects.create(user=user, place_id=place_detail, place_type=place_type)
                user_place_obj.save()

            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': "User {} Place saved.".format(place_type)
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class UpdateUserPlace(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')
            place_id = request.data.get('place_id')
            place_name = request.data.get('place_name')
            latitude = request.data.get('latitude')
            longitude = request.data.get('longitude')
            place_type = request.data.get('place_type')

            if not (place_id and latitude and longitude and place_name and place_type):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "Value missing."
                })

            with transaction.atomic():

                place_detail = PlaceDetail.objects.filter(place_id=place_id).first()
                if not place_detail:
                    place_detail = PlaceDetail.objects.create(
                        place_id=place_id,
                        place_name=place_name,
                        latitude=latitude,
                        longitude=longitude,
                    )
                    place_detail.save()

                place_obj = Place.objects.filter(user=user.id, place_type=place_type).first()
                if place_obj and place_obj.place_type != "Other":
                    place_obj.place_id = place_detail
                    place_obj.save()
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'place_id': place_obj.place_id.place_id,
                        'place_name': place_obj.place_id.place_name,
                        'place_type': place_obj.place_type,
                        'latitude': place_obj.place_id.latitude,
                        'longitude': place_obj.place_id.longitude,
                        'message': "{} Place updated.".format(place_obj.place_type)
                    })
                else:
                    user_place_obj = Place.objects.filter(user=user, place_id=place_detail, place_type=place_type).first()
                    if not user_place_obj:
                        user_place_obj = Place.objects.create(user=user, place_id=place_detail, place_type=place_type)
                        user_place_obj.save()
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'place_id': user_place_obj.place_id.place_id,
                        'place_name': user_place_obj.place_id.place_name,
                        'place_type': user_place_obj.place_type,
                        'latitude': user_place_obj.place_id.latitude,
                        'longitude': user_place_obj.place_id.longitude,
                        'message': "{} Place updated.".format(user_place_obj.place_type)
                    })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class UserPlaces(generics.GenericAPIView):

    @login_decorator
    def get(self, request, data=None):
        try:
            user = data.get('user')

            user_places = []
            user_obj = Place.objects.filter(user=user.id)
            if user_obj:
                for place in user_obj:
                    user_places.append({
                        'place_id': place.place_id.place_id, 'place_name': place.place_id.place_name,
                        'place_type': place.place_type, 'latitude': place.place_id.latitude,
                        'longitude': place.place_id.longitude
                    })

            return JsonResponse({
                'status': HTTP_200_OK,
                'places': user_places,
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })
