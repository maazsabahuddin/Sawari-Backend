import re
from functools import wraps
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_401_UNAUTHORIZED, HTTP_200_OK
from django.db import transaction
from A.settings.base import PHONE_NUMBER_REGEX, EMAIL_REGEX, COUNTRY_CODE_PK
from CustomAuthentication.backend_authentication import CustomUserCheck
from User.models import UserOtp, User
from User.exceptions import UserException, PinNotMatched, MissingField, UserNotFound, OldPin, \
    TwilioEmailException, InvalidUsage, WrongPassword, WrongPhonenumber, TemporaryUserMessage
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

        except (UserNotFound, MissingField) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': str(e.message),
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
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return decorated_function


def password_reset_decorator(f):
    @wraps(f)
    def match_uuid(*args):
        try:
            request = args[1]
            password_uuid = request.GET.get('password_uuid')
            email_or_phone = request.data.get('email_or_phone')

            email_or_phone = email_or_phone.strip()
            password_uuid = password_uuid.strip()

            if not email_or_phone:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Email/Phone is required'
                })

            phone_number = re.match(PHONE_NUMBER_REGEX, email_or_phone)
            email = re.search(EMAIL_REGEX, email_or_phone)
            if not phone_number and not email:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Email/Phone',
                })

            if not password_uuid:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No access.',
                })

            user_otp = UserOtp.objects.filter(password_reset_id=password_uuid).first()
            if not user_otp:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid uuid.',
                })

            # Check user Via Email and Phones
            user = CustomUserCheck.check_user(email_or_phone)
            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'Invalid Email/Phone.',
                })

            if user != user_otp.user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'User not matched.',
                })

            data = {'user': user_otp}
            return f(args[0], request, data)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return match_uuid


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

        except TwilioEmailException as e:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': str(e.message),
            })

        except (WrongPhonenumber, MissingField, TemporaryUserMessage) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return decorated_function


def otp_verify(f):
    @wraps(f)
    def token_decorator(*args):
        try:
            request = args[1]
            token = request.headers.get('authorization')
            otp = request.data.get('otp')
            email_or_phone = request.data.get('email_or_phone')
            email_or_phone = email_or_phone.strip()

            if not email_or_phone:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'Phone number required',
                })

            if email_or_phone[0] == "0":
                email_or_phone = "+" + COUNTRY_CODE_PK + email_or_phone[1:]

            # email_or_phone_user = User.objects.filter(phone_number=phone_number).first()
            email_or_phone_user = CustomUserCheck.check_user(email_or_phone)

            if not otp:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'otp required',
                })

            if not token:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'token required',
                })

            token_user = Token.objects.filter(key=token).first()
            if not token_user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Token.',
                })

            if not token_user.user == email_or_phone_user:
                return JsonResponse({
                    'status': HTTP_401_UNAUTHORIZED,
                    'message': 'duplicate user.',
                })

            context = {'user': token_user.user, 'otp': otp, 'email_or_phone': email_or_phone}
            return f(args[0], request, context)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return token_decorator


def change_phone_number_otp_verify(f):
    @wraps(f)
    def token_decorator(*args):
        try:
            request = args[1]
            user = args[2]['user']
            otp = request.data.get('otp')
            phone_number = request.data.get('phone_number')
            phone_number = phone_number.strip()

            if not phone_number:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'Phone number required',
                })

            if phone_number[0] == "0":
                phone_number = "+" + COUNTRY_CODE_PK + phone_number[1:]

            if not otp:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'otp required',
                })

            context = {'user': user, 'otp': otp, 'phone_number': phone_number}
            return f(args[0], request, context)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

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
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })

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
            confirm_password = data('confirm_password')
            is_customer = data('is_customer')
            register_via = data('via')
            first_name = data('first_name')

            email = email.strip()
            phone_number = phone_number.strip()

            if register_via == "google":
                register_via_google(email, first_name)

            if not phone_number:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Phone number is required.',
                })

            if not password and not confirm_password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Password Field required.',
                })

            # Checking Validation
            first_name = ''
            if email:
                from User.views_designpatterns import UserMixinMethods
                if not UserMixinMethods.validate_email(email):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Email.',
                    })
                first_name = email.split('@')[0]

            # Checking Validation
            if phone_number:
                if phone_number[0] == "0":
                    phone_number = "+" + COUNTRY_CODE_PK + phone_number[1:]

                if len(phone_number) != 13:
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Phone Number',
                    })

                from User.views_designpatterns import UserMixinMethods
                if not UserMixinMethods.validate_phone(phone_number):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Phone Number',
                    })

            if is_customer == 'False':
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'is_customer field should be true',
                })

            if password != confirm_password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Password Fields not matched'
                })

            if not email and not phone_number:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Email/Phone is required'
                })

            data = {
                'email': email,
                'phone_number': phone_number,
                'password': password,
                'is_customer': is_customer,
                'first_name': first_name,
            }
            return f(args[0], request, data)

        except UserException as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })

    return register_decorator


def logout_decorator(f):
    @wraps(f)
    def decorated_function(*args):
        try:
            request = args[1]
            token = request.headers['authorization']

            if not token:
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'Token required for authentication.',
                })

            user_token = Token.objects.filter(key=token).first()
            if not user_token:
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'Logged out.',
                })

            return f(args[0], request, user=user_token)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem ' + str(e),
            })

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
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return resend_otp_function


def resend_otp_change_phone_number(f):
    def resend_otp_function(*args):
        try:
            request = args[1]
            user = args[2]['user']
            phone_number = request.data.get('phone_number')

            phone_number = phone_number.strip()

            if not phone_number:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "Phone Number required."
                })

            if not (not (phone_number[0] != "0") or not (phone_number[0] != "+")):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Phonenumber',
                })

            if phone_number[0] == "0":
                phone_number = "+" + COUNTRY_CODE_PK + phone_number[1:]

            from User.views_designpatterns import UserMixinMethods
            if not UserMixinMethods.validate_phone(phone_number):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Phone Number',
                })

            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'User not found.',
                })

            data = {'user': user, 'phone_number': phone_number}
            return f(args[0], request, data)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return resend_otp_function


def phone_number_decorator(f):
    def phone_number_function(*args):
        try:
            request = args[1]
            user = args[2]['user']
            phone_number = request.data.get('phonenumber')
            phone_number = phone_number.strip()

            if not phone_number:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "Phone Number required."
                })

            if not (not (phone_number[0] != "0") or not (phone_number[0] != "+")):
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'Invalid Phonenumber',
                })

            if phone_number[0] == "0":
                phone_number = "+" + COUNTRY_CODE_PK + phone_number[1:]

            if len(phone_number) != 13:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Phone Number',
                })

            from User.views_designpatterns import UserMixinMethods
            if not UserMixinMethods.validate_phone(phone_number):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Phone Number',
                })

            if phone_number == user.phone_number:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'This phone number already set to your account.',
                })

            user_exist = CustomUserCheck.check_user(phone_number)
            if user_exist:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "User with this Phone Number already exists."
                })

            return f(args[0], request, user=user, phonenumber=phone_number)

        # except UserException as e:
        #     return JsonResponse({
        #         'status': HTTP_400_BAD_REQUEST,
        #         'message': 'Server problem' + str(e),
        #     })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return phone_number_function


def password_change_decorator(f):
    def password_change(*args):
        try:
            request = args[1]
            user = args[2]['user']
            # previous_pin = request.data.get('previous_pin')
            pin = request.data.get('pin')
            confirm_pin = request.data.get('confirm_pin')

            # previous_pin = previous_pin.strip()
            pin = pin.strip()
            confirm_pin = confirm_pin.strip()

            if not user:
                raise UserException(status_code=404)

            if not (pin and confirm_pin):
                raise UserException(status_code=405)

            if pin != confirm_pin:
                raise UserException(status_code=406)

            if user.check_password(pin):
                raise UserException(status_code=407)

            # from django.contrib.auth.hashers import make_password
            # pin = make_password(pin)
            # if user.password == pin:
            #     raise UserException(status_code=407)

            # if new_pin == previous_pin:
            #     raise UserException(status_code=407)

            context = {
                'user': user,
                'new_pin': pin,
                'confirm_new_pin': confirm_pin,
            }

            return f(args[0], request, context)

        except UserException as e:
            if e.status_code == 401:
                raise WrongPassword(message='Previous pin is not correct.')
            if e.status_code == 404:
                raise UserNotFound(message="User not found.")
            elif e.status_code == 405:
                raise MissingField(message="Field missing.")
            if e.status_code == 406:
                raise PinNotMatched(message="Password Fields not matched.")
            elif e.status_code == 407:
                raise OldPin(message="You cannot set old pin as new pin.")

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })

    return password_change
