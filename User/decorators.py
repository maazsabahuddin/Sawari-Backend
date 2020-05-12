import re
from functools import wraps
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_401_UNAUTHORIZED, HTTP_200_OK
from django.db import transaction
from A.settings.base import PHONE_NUMBER_REGEX, EMAIL_REGEX, COUNTRY_CODE_PK, NOT_CATCHABLE_ERROR_CODE, \
    NOT_CATCHABLE_ERROR_MESSAGE
from CustomAuthentication.backend_authentication import CustomUserCheck
from User.models import UserOtp, User
from User.exceptions import UserException, PinNotMatched, MissingField, UserNotFound, OldPin, \
     InvalidUsage, WrongPassword, WrongPhonenumber, TemporaryUserMessage, MisMatchField, DuplicateUser, TwilioException
from RideSchedule.exceptions import RideFare, RideException, RideNotAvailable, FieldMissing, NotEnoughSeats, \
    StopNotExist
from Payment.exceptions import PaymentException, PaymentMethodException, Fare
import uuid
from django.contrib.auth.hashers import make_password


def login_decorator(f):
    @wraps(f)
    def decorated_function(*args):
        try:
            request = args[1]
            token = request.headers.get('authorization')

            if not token:
                raise MissingField(status_code=HTTP_400_BAD_REQUEST, message='Token required for authentication.')

            user_token = Token.objects.filter(key=token).first()
            if not user_token:
                raise UserNotFound(status_code=HTTP_404_NOT_FOUND, message='Login session expire.')

            user = CustomUserCheck.check_user_separately(user_token.user.email, user_token.user.phone_number)

            data = {'user': user}
            return f(args[0], request, data)

        except (UserNotFound, MissingField, DuplicateUser, UserException) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })

        except PinNotMatched as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e.message),
            })

        except OldPin as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e.message),
            })

        except RideNotAvailable as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
            })

        except NotEnoughSeats as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
            })

        except FieldMissing as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
            })

        except StopNotExist as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
            })

        except PaymentMethodException as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
            })

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})

    return decorated_function


def password_reset_decorator(f):
    @wraps(f)
    def match_uuid(*args):
        from .views_designpatterns import UserMixinMethods
        try:
            request = args[1]
            email_or_phone = request.data.get('email_or_phone')
            email_or_phone = email_or_phone.strip()

            if not email_or_phone:
                raise MissingField(status_code=400, message='Email/Phone required.')

            if email_or_phone[0] == "0":
                email_or_phone = "+" + COUNTRY_CODE_PK + email_or_phone[1:]

            if email_or_phone[0] == "+":
                if len(email_or_phone) != 13 or not UserMixinMethods.validate_phone(email_or_phone):
                    raise WrongPhonenumber(status_code=400, message='Invalid Email/Phone.')

            elif not UserMixinMethods.validate_email(email_or_phone):
                raise WrongPhonenumber(status_code=400, message='Invalid Email/Phone.')

            # Check if user exist or not.
            user = CustomUserCheck.check_user(email_or_phone)
            if not user:
                raise UserNotFound(status_code=400,
                                   message='The sign-in credentials does not exist. Try again or create a new account.')

            data = {'user': user}
            return f(args[0], request, data)

        except (MissingField, WrongPhonenumber, UserNotFound) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})

    return match_uuid


def password_reset_link(f):
    @wraps(f)
    def reset_link_check(*args):
        try:
            request = args[0]
            token_uuid = request.GET.get('token_uuid')
            token_uuid = token_uuid.strip()

            if not token_uuid:
                raise MissingField(status_code=400, message='Invalid link.')

            # Check if user exist or not.
            user = UserOtp.objects.filter(password_reset_id=token_uuid).first()
            if not user:
                raise UserNotFound(status_code=400, message='Invalid link.')

            data = {'user': user.user}
            return f(args[0], request, data)

        except (MissingField, UserNotFound) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})

    return reset_link_check


def login_credentials(f):
    @wraps(f)
    def decorated_function(*args):
        try:
            request = args[1]
            email_or_phone = request.data.get("email_or_phone")
            password = request.data.get('password')
            app = request.data.get('app')

            app = app.strip()
            email_or_phone = email_or_phone.strip()
            password = password.strip()

            if app == "Captain":
                raise TemporaryUserMessage(status_code=400, message='Captain app coming soon.')

            if not password:
                raise MissingField(status_code=400, message='Password required.')

            if not email_or_phone:
                raise MissingField(status_code=400, message='Email/Phone required.')

            if not app:
                raise MissingField(status_code=400, message='App not mentioned.')

            if email_or_phone[0] == "0":
                email_or_phone = "+" + COUNTRY_CODE_PK + email_or_phone[1:]

            from User.views_designpatterns import UserMixinMethods
            if len(email_or_phone) != 13 or not UserMixinMethods.validate_phone(email_or_phone):
                raise WrongPhonenumber(status_code=400, message='Invalid Phonenumber')

            data = {'email_or_phone': email_or_phone, 'password': password, 'app': app}
            return f(args[0], request, data)

        except (WrongPhonenumber, MissingField, TemporaryUserMessage, TwilioException) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})

    return decorated_function


def verify_user(f):
    @wraps(f)
    def token_decorator(*args):
        request = args[1]
        user = args[2].get('user')
        otp = request.data.get('otp')
        email_or_phone = request.data.get('email_or_phone')

        email_or_phone = email_or_phone.strip()
        otp = otp.strip()

        if not (email_or_phone and user and otp):
            raise MissingField(status_code=400, message='email_phone/otp required.')

        if email_or_phone[0] == "0":
            email_or_phone = "+" + COUNTRY_CODE_PK + email_or_phone[1:]

        from User.views_designpatterns import UserMixinMethods
        if len(email_or_phone) != 13 or not UserMixinMethods.validate_phone(email_or_phone):
            raise WrongPhonenumber(status_code=400, message='Invalid Phonenumber')

        user_email_or_phone = CustomUserCheck.check_user(email_or_phone)
        if not user == user_email_or_phone:
            raise DuplicateUser(status_code=409, message='Duplicate user.')

        if user.is_active:
            return JsonResponse({'status': HTTP_200_OK, 'message': 'User already verified'})

        data = {'user': user, 'otp': otp, 'email_or_phone': email_or_phone}
        return f(args[0], request, data)

    return token_decorator


def change_phone_number_otp_verify(f):
    @wraps(f)
    def token_decorator(*args):
        request = args[1]
        user = args[2].get('user')
        otp = request.data.get('otp')
        phone_number = request.data.get('phone_number')

        otp = otp.strip()
        phone_number = phone_number.strip()

        if not phone_number or not otp:
            raise MissingField(status_code=400, message='Phonenumber required.')

        if phone_number[0] == "0":
            phone_number = "+" + COUNTRY_CODE_PK + phone_number[1:]

        from User.views_designpatterns import UserMixinMethods
        if len(phone_number) != 13 or not UserMixinMethods.validate_phone(phone_number):
            raise WrongPhonenumber(status_code=400, message='Invalid Phonenumber')

        if user:
            raise WrongPhonenumber(status_code=400, message='API locked.')

        data = {'user': user, 'otp': otp, 'phone_number': phone_number}
        return f(args[0], request, data)

    return token_decorator


def register_or_login_google(f):

    def decorator(*args):
        try:
            request = args[1]
            email = request.data.get('email')
            name = request.data.get('name')
            app = request.data.get('app')

            email = email.strip()
            name = name.strip()
            app = app.strip()

            from User.views_designpatterns import UserMixinMethods
            if not UserMixinMethods.validate_email(email):
                raise UserException(status_code=400, message='Invalid Email address')

            password = None
            user = CustomUserCheck.check_user(email)
            if not user:
                password = uuid.uuid4()
                password = make_password(password)

            data = {
                'email': email,
                'password': password,
                'app': app,
                'name': name,
            }
            return f(args[0], request, data)

        except UserException as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})

    return decorator


def register(f):
    @wraps(f)
    def register_decorator(*args):
        try:
            request = args[1]
            data = request.data.get
            email = data('email')
            phone_number = data('phone_number')
            password = data('password')
            app = data('app')
            first_name = data('first_name')

            email = email.strip()
            phone_number = phone_number.strip()
            app = app.strip()
            first_name = first_name.strip()
            password = password.strip()

            if app == "Captain":
                raise TemporaryUserMessage(status_code=400, message='Captain app coming soon.')
            if not phone_number:
                raise MissingField(status_code=400, message='Phone number is required.')
            if not password:
                raise MissingField(status_code=400, message='Password field required.')
            if not app:
                raise MissingField(status_code=400, message='App field required.')

            if not first_name:
                first_name = ''

            if email:
                from User.views_designpatterns import UserMixinMethods
                if not UserMixinMethods.validate_email(email):
                    raise MisMatchField(status_code=400, message='Invalid email address.')
                first_name = email.split('@')[0]

            # Checking Validation
            if phone_number[0] == "0":
                phone_number = "+" + COUNTRY_CODE_PK + phone_number[1:]

            from User.views_designpatterns import UserMixinMethods
            if len(phone_number) != 13 or not UserMixinMethods.validate_phone(phone_number):
                raise WrongPhonenumber(status_code=400, message='Invalid Phonenumber')

            data = {
                'email': email,
                'phone_number': phone_number,
                'password': password,
                'app': app,
                'first_name': first_name,
            }
            return f(args[0], request, data)

        except (WrongPhonenumber, MissingField, TemporaryUserMessage, MisMatchField) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})

    return register_decorator


def logout_decorator(f):
    @wraps(f)
    def decorated_function(*args):
        try:
            request = args[1]
            token = request.headers['authorization']

            if not token:
                raise MissingField(status_code=400, message='Token required for authentication.')

            user_token = Token.objects.filter(key=token).first()
            if not user_token:
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'Logged out.',
                })
            return f(args[0], request, user=user_token)

        except MissingField as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })
        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})

    return decorated_function


def resend_otp(f):
    def resend_otp_function(*args):
        try:
            request = args[1]
            token = request.headers.get('authorization')

            if not token:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Token required for authentication.',
                })

            user_token = Token.objects.filter(key=token).first()
            if not user_token:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Token.',
                })

            user = CustomUserCheck.check_user_separately(user_token.user.email, user_token.user.phone_number)

            data = {'user': user}
            return f(args[0], request, data)

        except Exception as e:
            return JsonResponse({'status': NOT_CATCHABLE_ERROR_CODE, 'message': NOT_CATCHABLE_ERROR_MESSAGE})

    return resend_otp_function


def resend_otp_change_phone_number(f):
    def resend_otp_function(*args):

        request = args[1]
        user = args[2].get('user')
        phone_number = request.data.get('phone_number')

        phone_number = phone_number.strip()

        if not phone_number:
            raise MissingField(status_code=400, message='Phone number is required.')

        # Checking Validation
        if phone_number[0] == "0":
            phone_number = "+" + COUNTRY_CODE_PK + phone_number[1:]

        from User.views_designpatterns import UserMixinMethods
        if len(phone_number) != 13 or not UserMixinMethods.validate_phone(phone_number):
            raise WrongPhonenumber(status_code=400, message='Invalid Phonenumber')

        if user:
            raise WrongPhonenumber(status_code=400, message='API locked.')

        data = {'user': user, 'phone_number': phone_number}
        return f(args[0], request, data)

    return resend_otp_function


def phone_number_decorator(f):
    def phone_number_function(*args):
        request = args[1]
        user = args[2].get('user')
        phone_number = request.data.get('phonenumber')
        phone_number = phone_number.strip()

        if not phone_number:
            raise MissingField(status_code=400, message='Phone number is required.')

        # Checking Validation
        if phone_number[0] == "0":
            phone_number = "+" + COUNTRY_CODE_PK + phone_number[1:]

        from User.views_designpatterns import UserMixinMethods
        if len(phone_number) != 13 or not UserMixinMethods.validate_phone(phone_number):
            raise WrongPhonenumber(status_code=400, message='Invalid Phonenumber')

        if phone_number == user.phone_number:
            raise WrongPhonenumber(status_code=400, message='This phone number already set to your account.')

        user2 = CustomUserCheck.check_user(phone_number)
        if user2 and user2.is_active:
            raise WrongPhonenumber(status_code=400, message='User with this Phone Number already exists.')

        # Temporary Message
        if user:
            raise WrongPhonenumber(status_code=400, message='API locked.')

        return f(args[0], request, user=user, phonenumber=phone_number)

    return phone_number_function


def password_change_decorator(f):
    def password_change(*args):
        request = args[1]
        user = args[2].get('user')
        pin = request.data.get('pin')

        pin = pin.strip()
        if not user:
            raise MissingField(status_code=400, message="Pin required")

        if user.check_password(pin):
            raise UserException(status_code=400, message="You cannot set old pin as new pin.")

        data = {'user': user, 'pin': pin}
        return f(args[0], request, data)

    return password_change
