import re
from functools import wraps
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_401_UNAUTHORIZED

from A.settings import PHONE_NUMBER_REGEX, EMAIL_REGEX, COUNTRY_CODE_PK
from CustomAuthentication.backend_authentication import CustomUserCheck
from User.models import UserOtp
# from User.views_designpatterns import UserMixinMethods


def login_decorator(f):

    @wraps(f)
    def decorated_function(*args):
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
                    'status': HTTP_401_UNAUTHORIZED,
                    'message': 'Invalid Token.',
                })

            user = CustomUserCheck.check_user_separately(user_token.user.email, user_token.user.phone_number)

            if not user.is_active:
                return JsonResponse({
                    'status': HTTP_401_UNAUTHORIZED,
                    'message': 'User not authenticated. Please verify first.',
                })

            data = {'user': user}
            return f(args[0], request, data)

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

            if not password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Password required.',
                })

            if not email_or_phone:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Email/Phone required.',
                })

            if email_or_phone[0] == "0":
                email_or_phone = "+" + COUNTRY_CODE_PK + email_or_phone[1:]

            context = {'email_or_phone': email_or_phone, 'password': password}
            return f(args[0], request, context)

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

            context = {'user': token_user.user, 'otp': otp}
            return f(args[0], request, context)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return token_decorator


def register(f):

    @wraps(f)
    def register_decorator(*args):
        request = args[1]
        data = request.data.get
        email = data('email')
        phone_number = data('phone_number')
        password = data('password')
        confirm_password = data('confirm_password')
        is_customer = data('is_customer')

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

        context = {
            'email': email,
            'phone_number': phone_number,
            'password': password,
            'is_customer': is_customer,
            'first_name': first_name,
        }
        return f(args[0], request, context)

    return register_decorator


def logout_decorator(f):

    @wraps(f)
    def decorated_function(*args):
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


def phone_number_decorator(f):

    def phone_number_function(*args):
        try:
            request = args[1]
            user = args[2]['user']
            phone_number = request.data.get('phonenumber')

            if not phone_number:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "Phone Number required."
                })

            # Checking Validation
            if phone_number:
                print(phone_number[0])
                if phone_number[0] != ("0" or "+"):
                    return JsonResponse({
                        'status': HTTP_404_NOT_FOUND,
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

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return phone_number_function
