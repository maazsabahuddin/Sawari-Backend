import datetime
import re
import uuid
from abc import abstractmethod, ABCMeta
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.http import JsonResponse
from django_twilio.client import Client

from rest_framework import generics
from rest_framework.permissions import AllowAny
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView

from A.settings.base import TWILIO_AUTH_TOKEN, TWILIO_ACCOUNT_SID, OTP_INITIAL_COUNTER, EMAIL_REGEX, \
    PHONE_NUMBER_REGEX, EMAIL_VERIFICATION, PHONE_VERIFICATION, COUNTRY_CODE_PK, NOT_CATCHABLE_ERROR_CODE, \
    NOT_CATCHABLE_ERROR_MESSAGE, OTP_COUNTER_LIMIT
from CustomAuthentication.backend_authentication import CustomAuthenticationBackend, CustomUserCheck
from User.decorators import login_credentials, login_decorator, register, password_reset_decorator, \
    logout_decorator, resend_otp, phone_number_decorator, password_change_decorator, resend_otp_change_phone_number, \
    change_phone_number_otp_verify, register_or_login_google, verify_user
from .models import User, Customer, UserOtp, Place, PlaceDetail, Captain
from User.otp_verify import UserOTPMixin
from User.exceptions import UserException, InvalidUsage, WrongPassword, \
    UserNotAuthorized, UserNotActive, MissingField, WrongPhonenumber, UserNotFound, UserAlreadyExist, \
    TemporaryUserMessage, MisMatchField, TwilioException, WrongOtp, PlaceException

account_sid = TWILIO_ACCOUNT_SID
auth_token = TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)


class AppInterface:
    value = "Customer"

    @classmethod
    def app(cls, **kwargs):
        app = kwargs.get('value')
        if app != cls.value:
            return False
        return True


class CheckUser(generics.GenericAPIView):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # client_app = request.data.get('app')
        if not AppInterface.app(value="Customer"):
            raise NotImplementedError

    def post(self, request):
        try:
            phone_number = request.data.get("phone_number")
            app = request.data.get('app')

            phone_number = phone_number.strip()
            app = app.strip()

            if not phone_number or not app:
                raise MissingField(status_code=400, message='Phone required.')

            # Checking Validation
            if phone_number:
                if phone_number[0] == "0":
                    phone_number = "+" + COUNTRY_CODE_PK + phone_number[1:]

                if len(phone_number) != 13 or not UserMixinMethods.validate_phone(phone_number):
                    raise WrongPhonenumber(status_code=400, message='Invalid Phonenumber')

            # Check if user exist or not.
            user = CustomUserCheck.check_user(phone_number)
            if not user:
                with transaction.atomic():
                    email = None
                    user = User.objects.create(
                        phone_number=phone_number,
                        password=make_password(uuid.uuid4()),
                        is_active=False,
                    )
                    user.save()

                    if app == "Customer":
                        Customer.objects.create(user=user)
                        if user:
                            user.is_customer = True
                            user.save()
                            token, _ = Token.objects.get_or_create(user=user)
                    elif app == "Captain":
                        Captain.objects.create(user=user)
                        if user:
                            user.is_customer = True
                            user.save()
                            token, _ = Token.objects.get_or_create(user=user)
                    else:
                        raise TemporaryUserMessage(status_code=400,
                                                   message='Server temporary down. Sorry for inconvenience.')
                    otp = UserOTPMixin.generate_otp()
                    print(otp)

                    from django.utils import timezone
                    user_otp = UserOtp.objects.create(
                        user=user,
                        otp=otp,
                        otp_time=timezone.localtime(timezone.now()),
                        otp_counter=OTP_INITIAL_COUNTER,
                        is_verified=False,
                    )
                    user_otp.save()

                    # FACTORY PATTERN it delegates the decision to the get_serializer method and
                    # return the object of concrete/implementation method
                    serializer = UserMixinMethods.get_serializer_object_register(email, phone_number)
                    result_otp = serializer(otp, email=email, phone_number=phone_number)
                    if not result_otp:
                        user.is_active = True
                        user.save()
                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'token': token.key,
                            'message': 'User successfully registered.',
                        })

                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'token': token.key,
                        'message': 'OTP has been successfully sent.',
                    })

            if app == "Customer" and not user.is_customer:
                raise UserNotAuthorized(status_code=401, message='Not authorized to login in the app.')

            if app == "Captain" and not user.is_captain:
                raise UserNotAuthorized(status_code=401, message='Not authorized to login in the app.')

            token, _ = Token.objects.get_or_create(user=user)
            if not user.is_active:
                raise UserNotActive(status_code=401, message="User not authenticated. Please verify first.")

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'User Exist.'
            })

        except UserNotActive as e:
            otp = UserOTPMixin.generate_otp()
            print(otp)

            from django.utils import timezone
            user_otp = UserOtp.objects.filter(user=user).first()
            if not user_otp:
                user_otp = UserOtp.objects.create(user=user)
            if user_otp.otp_counter >= OTP_COUNTER_LIMIT:
                return JsonResponse({
                    'status': 401,
                    'message': "User not authenticated. Please contact Sawari helpline."
                })
            user_otp.otp = otp
            user_otp.otp_time = timezone.localtime(timezone.now())
            user_otp.otp_counter += 1
            user_otp.save()

            # FACTORY PATTERN it delegates the decision to the get_serializer method and
            # return the object of concrete/implementation method
            serializer = UserMixinMethods.get_serializer_object_register(user.email, user.phone_number)
            result_otp = serializer(otp, email=user.email, phone_number=user.phone_number)
            if not result_otp:
                user.is_active = True
                user.save()
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'token': token.key,
                    'message': 'User verified and login successfully.',
                })

            return JsonResponse({
                'status': HTTP_200_OK,
                'token': token.key,
                'message': 'OTP has been successfully sent.',
            })

        except (WrongPhonenumber, UserNotAuthorized, UserNotFound, MissingField, TemporaryUserMessage,
                TwilioException) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
            })

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


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
        from django.utils import timezone
        if not user:
            return False
        otp_counter = user.otp_counter
        otp_counter += 1
        user.otp = otp
        user.otp_time = timezone.localtime(timezone.now())
        user.is_verified = False
        user.otp_counter = otp_counter
        user.save()
        return True

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

    @login_decorator
    # @resend_otp
    def post(self, request, data=None):
        try:
            user = data.get('user')

            with transaction.atomic():
                otp = UserOTPMixin.generate_otp()

                from django.utils import timezone
                user_otp = UserOtp.objects.filter(user=user).first()
                if not user_otp:
                    user_otp = UserOtp.objects.create(user=user)
                if user_otp.otp_counter >= OTP_COUNTER_LIMIT:
                    return JsonResponse({
                        'status': 401,
                        'message': "User not authenticated. Please contact Sawari helpline."
                    })
                user_otp.otp = otp
                user_otp.otp_time = timezone.localtime(timezone.now())
                user_otp.otp_counter += 1
                user_otp.save()

                # FACTORY PATTERN it delegates the decision to the get_serializer method and
                # return the object of concrete/implementation method
                serializer = UserMixinMethods.get_serializer_object_register(user.email, user.phone_number)
                result_otp = serializer(otp, email=user.email, phone_number=user.phone_number)
                if not result_otp:
                    return JsonResponse({'status': 400, 'message': 'Unable to resent the otp.'})

                return JsonResponse({'status': 200, 'message': 'OTP has been successfully resent.'})

        except (MisMatchField, TwilioException, UserException) as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class LoginViaGoogle(generics.GenericAPIView):

    @register_or_login_google
    def post(self, request, data=None):
        token = None
        try:
            email = data.get('email')
            password = data.get('password')
            app = data.get('app')
            name = data.get('name')

            user = CustomUserCheck.check_user(email)
            if user and not password:
                user_name = user.first_name + " " + user.last_name
                user_name = user_name.strip()
                if not user.is_active or user_name != name:
                    raise UserNotActive(status_code=401,
                                        message="User not authenticated. Please contact Sawari helpline.")

                if app == "Customer" and not user.is_customer:
                    raise UserNotAuthorized(status_code=401, message='Not authorized to login in the app.')

                if app == "Captain" and not user.is_captain:
                    raise UserNotAuthorized(status_code=401, message='Not authorized to login in the app.')

                token, _ = Token.objects.get_or_create(user=user)
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'token': token.key,
                    'message': 'Login Successfully',
                })

            with transaction.atomic():
                user = User.objects.create(
                    first_name=name,
                    email=email,
                    phone_number=None,
                    password=password,
                    is_active=True,
                )
                user.save()

                if app == "Customer":
                    Customer.objects.create(user=user)
                    if user:
                        user.is_customer = True
                        user.save()
                        token, _ = Token.objects.get_or_create(user=user)
                elif app == "Captain":
                    Captain.objects.create(user=user)
                    if user:
                        user.is_customer = True
                        user.save()
                        token, _ = Token.objects.get_or_create(user=user)
                else:
                    pass

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'token': token.key,
                    'message': 'User Registered successfully.',
                })

        except (UserNotAuthorized, UserNotActive) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
            })

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


# @singleton
class Register(RegisterCase, UserMixinMethods):

    permission_classes = (AllowAny,)

    def email_phone_otp(self, otp, **kwargs):
        email = kwargs.get('email')
        phone_number = kwargs.get('phone_number')

        if EMAIL_VERIFICATION:
            result_email = UserOTPMixin.send_otp_email(email, otp)
            if not result_email:
                raise MisMatchField(status_code=400, message='Invalid email address.')
            return True

        if PHONE_VERIFICATION:
            result_phone_number = UserOTPMixin.send_otp_phone(phone_number, otp)
            if not result_phone_number:
                raise TwilioException(status_code=400,
                                      message=phone_number + " is not verified on your Twilio trial account.")
            return True
        return False

    def email_otp(self, otp, **kwargs):
        email = kwargs.get('email')

        # Sending OTP Via Email
        if EMAIL_VERIFICATION:
            result_email = UserOTPMixin.send_otp_email(email, otp)
            if not result_email:
                raise MisMatchField(status_code=400, message='Invalid email address.')
            return True
        return False

    def phone_otp(self, otp, **kwargs):
        phone_number = kwargs.get('phone_number')

        # Sending OTP Via Phone
        if PHONE_VERIFICATION:
            result_phone_number = UserOTPMixin.send_otp_phone(phone_number, otp)
            if not result_phone_number:
                raise TwilioException(status_code=400,
                                      message=phone_number + " is not verified on your Twilio trial account.")
            return True
        return False

    @register
    def post(self, request, data=None):
        token = None
        try:
            email = data.get('email')
            phone_number = data.get('phone_number')
            password = data.get('password')
            app = data.get('app')
            first_name = data.get('first_name')

            user_email = User.objects.filter(email=email).first()
            user_phone_no = User.objects.filter(phone_number=phone_number).first()
            if user_email or user_phone_no:
                raise UserAlreadyExist(status_code=400, message='Email/Phone already registered.')

            with transaction.atomic():

                if not email:
                    email = None
                user = User.objects.create(
                    first_name=first_name,
                    email=email,
                    phone_number=phone_number,
                    password=make_password(password),
                    is_active=False,
                )
                user.save()

                if app == "Customer":
                    Customer.objects.create(user=user)
                    if user:
                        user.is_customer = True
                        user.save()
                        token, _ = Token.objects.get_or_create(user=user)
                elif app == "Captain":
                    Captain.objects.create(user=user)
                    if user:
                        user.is_customer = True
                        user.save()
                        token, _ = Token.objects.get_or_create(user=user)
                else:
                    raise TemporaryUserMessage(status_code=400,
                                               message='Server temporary down. Sorry for inconvenience.')
                otp = UserOTPMixin.generate_otp()
                print(otp)
                # FACTORY PATTERN it delegates the decision to the get_serializer method and
                # return the object of concrete/implementation method
                serializer = UserMixinMethods.get_serializer_object_register(email, phone_number)
                result_otp = serializer(otp, email=email, phone_number=phone_number)
                if not result_otp:
                    user.is_active = True
                    user.save()
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'token': token.key,
                        'message': 'User successfully registered.',
                    })

                from django.utils import timezone
                user_otp = UserOtp.objects.create(
                    user=user,
                    otp=otp,
                    otp_time=timezone.localtime(timezone.now()),
                    otp_counter=OTP_INITIAL_COUNTER,
                    is_verified=False,
                )
                user_otp.save()

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'token': token.key,
                    'message': 'OTP has been successfully sent.',
                })

        except (UserAlreadyExist, TemporaryUserMessage, TwilioException, MisMatchField) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class VerifyUser(generics.GenericAPIView, UserOTPMixin):

    @staticmethod
    def verify_otp(user, otp):

        otp_result = UserOTPMixin.verify_user_otp(user, otp)
        if not otp_result:
            return False
        user.is_active = True
        user.save()
        return True

    @login_decorator
    @verify_user
    def post(self, request, data=None):
        try:
            user = data.get('user')
            otp = data.get('otp')

            result = VerifyUser.verify_otp(user, otp)
            if not result:
                raise WrongOtp(status_code=401, message="OTP not matched.")

            return JsonResponse({'status': HTTP_200_OK, 'message': 'User verified.'})

        except (UserException, WrongOtp, UserNotFound) as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


# User Login - Customer / Captain
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
                raise UserNotFound(status_code=HTTP_404_NOT_FOUND,
                                   message='The sign-in credentials does not exist. Try again or create a new account')

            if app == "Customer" and not user_check.is_customer:
                raise UserNotAuthorized(status_code=401, message='Not authorized to login in the app.')

            if app == "Captain" and not user_check.is_captain:
                raise UserNotAuthorized(status_code=401, message='Not authorized to login in the app.')

            user = CustomAuthenticationBackend.authenticate(email_or_phone, password)
            if not user:
                raise WrongPassword(status_code=401, message="Invalid Credentials.")

            token, _ = Token.objects.get_or_create(user=user)
            if not user.is_active:
                raise UserNotActive(status_code=401, message="User not authenticated. Please verify first.")

            return JsonResponse({
                'status': HTTP_200_OK,
                'token': token.key,
                'message': 'Login Successfully',
            })

        except UserNotActive as e:
            otp = UserOTPMixin.generate_otp()
            print(otp)

            from django.utils import timezone
            user_otp = UserOtp.objects.filter(user=user).first()
            if not user_otp:
                user_otp = UserOtp.objects.create(user=user)
            if user_otp.otp_counter >= OTP_COUNTER_LIMIT:
                return JsonResponse({
                    'status': 401,
                    'message': "User not authenticated. Please contact Sawari helpline."
                })
            user_otp.otp = otp
            user_otp.otp_time = timezone.localtime(timezone.now())
            user_otp.otp_counter += 1
            user_otp.save()

            # FACTORY PATTERN it delegates the decision to the get_serializer method and
            # return the object of concrete/implementation method
            serializer = UserMixinMethods.get_serializer_object_register(user.email, user.phone_number)
            result_otp = serializer(otp, email=user.email, phone_number=user.phone_number)
            if not result_otp:
                user.is_active = True
                user.save()
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'token': token.key,
                    'message': 'User verified and login successfully.',
                })

            return JsonResponse({
                'status': HTTP_200_OK,
                'token': token.key,
                'message': 'OTP has been successfully sent.',
            })
        except (WrongPassword, UserNotAuthorized, UserNotFound, TwilioException) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
            })

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class UserLogout(APIView):

    @login_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')
            user_token = Token.objects.filter(user=user).first()

            is_logout = user_token.user.auth_token.delete()
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
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


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
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


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

                if VerifyUser.verify_otp(user_otp.user, otp):
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'message': 'Verified',
                    })

                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'OTP not matched.',
                })

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


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
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


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
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


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

    @login_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')

            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name')

            if not (first_name or last_name):
                raise MissingField(status_code=400, message='Some field missing.')

            if not first_name:
                first_name = user.first_name

            if not last_name:
                last_name = user.last_name

            if UpdateName.check_string_for_numbers(first_name=first_name, last_name=last_name):
                raise InvalidUsage(status_code=400, message='Name cannot contain digits.')

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

        except (MissingField, InvalidUsage) as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class ChangePhoneNumber(generics.GenericAPIView, UserOTPMixin):

    # QUERY AGAINST CHANGING PHONE NUMBER. WHAT WE DO? WE CREATE THE NEW USER OF THAT PHONE NUMBER OR WE DIRECTLY
    # CHANGE THE PHONE NUMBER OF THAT USER.
    @login_decorator
    @phone_number_decorator
    def post(self, request, **kwargs):
        try:
            user = kwargs.get('user')
            phone_number = kwargs.get('phonenumber')

            with transaction.atomic():
                otp = UserOTPMixin.generate_otp()
                print(otp)
                from django.utils import timezone

                user_otp = UserOtp.objects.create(user=user)
                if user_otp.otp_counter >= OTP_COUNTER_LIMIT:
                    return JsonResponse({
                        'status': 401,
                        'message': "Please contact Sawari helpline. This {} phonenumber is blocked.".format(phone_number)
                    })
                user_otp.otp = otp
                user_otp.otp_time = timezone.localtime(timezone.now())
                user_otp.otp_counter += 1
                user_otp.save()

                email = None
                # FACTORY PATTERN it delegates the decision to the get_serializer method and
                # return the object of concrete/implementation method
                serializer = UserMixinMethods.get_serializer_object_register(email, phone_number)
                result_otp = serializer(otp, email=email, phone_number=phone_number)
                if not result_otp:
                    user.is_active = True
                    user.save()
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'message': 'Phonenumber successfully changed.',
                    })

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'OTP has been successfully sent.',
                })

        except (TwilioException, UserException) as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class ChangePhoneNumberOtpMatch(generics.GenericAPIView):

    @login_decorator
    @change_phone_number_otp_verify
    def post(self, request, data=None):
        try:
            user = data.get('user')
            otp = data.get('otp')
            phone_number = data.get('phone_number')

            result = VerifyUser.verify_otp(user, otp)
            if not result:
                raise WrongOtp(status_code=401, message="OTP not matched.")

            user.phone_number = phone_number
            user.save()
            return JsonResponse({'status': HTTP_200_OK, 'message': 'Phonenumber successfully changed.'})

        except (UserException, WrongOtp, UserNotFound) as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class PasswordChange(generics.GenericAPIView):

    @login_decorator
    @password_change_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')
            new_pin = data.get('pin')

            user.set_password(new_pin)
            user.save()
            return JsonResponse({'status': HTTP_200_OK, 'message': 'Password has been changed.'})

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class PasswordCheck(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')
            password = request.data.get('password')

            password = password.strip()
            if not user.check_password(password):
                raise UserException(status_code=401 , message="Invalid password.")

            return JsonResponse({'status': HTTP_200_OK, 'message': 'Password Verified.'})

        except UserException as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class UserDetails(generics.GenericAPIView):

    @login_decorator
    def get(self, request, data=None):
        try:
            user = data.get('user')

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
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class DeleteUser(generics.GenericAPIView):

    @login_decorator
    def get(self, request, data=None):
        try:
            user = data.get('user')

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
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class PasswordChangeResendOtp(generics.GenericAPIView):

    @login_decorator
    @resend_otp_change_phone_number
    def post(self, request, data=None):
        try:
            user = data.get('user')
            phone_number = data.get('phone_number')

            with transaction.atomic():
                otp = UserOTPMixin.generate_otp()

                from django.utils import timezone
                user_otp = UserOtp.objects.filter(user=user).first()
                if not user_otp:
                    user_otp = UserOtp.objects.create(user=user)
                if user_otp.otp_counter >= OTP_COUNTER_LIMIT:
                    return JsonResponse({
                        'status': 401,
                        'message': "User not authenticated. Please contact Sawari helpline."
                    })
                user_otp.otp = otp
                user_otp.otp_time = timezone.localtime(timezone.now())
                user_otp.otp_counter += 1
                user_otp.save()

                # FACTORY PATTERN it delegates the decision to the get_serializer method and
                # return the object of concrete/implementation method
                email = None
                serializer = UserMixinMethods.get_serializer_object_register(email, phone_number)
                result_otp = serializer(otp, email=user.email, phone_number=user.phone_number)
                if not result_otp:
                    return JsonResponse({'status': 400, 'message': 'Unable to resent the otp.'})

                return JsonResponse({'status': 200, 'message': 'OTP has been successfully resent.'})

        except (MisMatchField, TwilioException, UserException) as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class UpdateEmail(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')
            email = request.data.get('email')

            email = email.strip()
            if not email:
                raise MissingField(status_code=400, message='Email required.')
            if user.email == email:
                raise MissingField(status_code=400, message=email + ' already set to your account.')
            if not UserMixinMethods.validate_email(email):
                raise MissingField(status_code=400, message='Invalid email address.')

            with transaction.atomic():
                user.email = email
                user.save()
            return JsonResponse({'status': HTTP_200_OK, 'message': "Email updated successfully."})

        except MissingField as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


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
                raise MissingField(status_code=400, message='Some field missing.')

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

        except MissingField as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


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
            address = request.data.get('address')

            place_id = place_id.strip()
            place_type = place_type.strip()
            place_name = place_name.strip()
            address = address.strip()
            latitude = latitude.strip()
            longitude = longitude.strip()

            if not (place_id and latitude and longitude and place_name and place_type and address):
                raise MissingField(status_code=400, message='Some field missing.')

            with transaction.atomic():

                place_detail = PlaceDetail.objects.filter(place_id=place_id).first()
                if not place_detail:
                    place_detail = PlaceDetail.objects.create(
                        place_id=place_id,
                        place_name=place_name,
                        place_address=address,
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
                        'place_address': place_obj.place_id.place_address,
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
                        'place_address': user_place_obj.place_id.place_address,
                        'latitude': user_place_obj.place_id.latitude,
                        'longitude': user_place_obj.place_id.longitude,
                        'message': "{} Place updated.".format(user_place_obj.place_type)
                    })

        except MissingField as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


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

            return JsonResponse({'status': HTTP_200_OK, 'places': user_places})

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})


class DeleteUserPlace(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')
            place_id = request.data.get('place_id')
            place_type = request.data.get('place_type')

            place_id = place_id.strip()
            place_type = place_type.strip()

            if not (place_id and place_type):
                raise MissingField(status_code=400, message='Some field missing.')

            user_place = Place.objects.filter(user=user.id, place_id__place_id=place_id, place_type=place_type).first()
            if not user_place:
                raise PlaceException(status_code=400, message='No such place exist.')
            user_place.delete()
            return JsonResponse({'status': HTTP_200_OK, 'places': 'User place removed.'})

        except (MissingField, PlaceException) as e:
            return JsonResponse({'status': e.status_code, 'message': e.message})
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})