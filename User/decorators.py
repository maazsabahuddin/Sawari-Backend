from functools import wraps
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND

from CustomAuthentication.backend_authentication import CustomUserCheck
from User.models import UserOtp


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
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Token.',
                })

            user = CustomUserCheck.check_user_seperately(user_token.user.email, user_token.user.phone_number)

            if not user.is_active:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
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

            if not password_uuid:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No access.',
                })
            user = UserOtp.objects.filter(password_reset_id=password_uuid).first()
            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid uuid.',
                })

            data = {'user': user}
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

            if token_user.user.is_active:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Already Verified',
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

        if not password and not confirm_password:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Password Field required.',
            })

        # Checking Validation
        if email:
            from User.views_designpatterns import UserMixinMethods
            UserMixinMethods.validate_email(email)

        # Checking Validation
        if phone_number:
            from User.views_designpatterns import UserMixinMethods
            UserMixinMethods.validate_phone(phone_number)

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

        context = {'email': email, 'phone_number': phone_number, 'password': password, 'is_customer': is_customer}
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

            user = CustomUserCheck.check_user_seperately(user_token.user.email, user_token.user.phone_number)

            data = {'user': user}
            return f(args[0], request, data)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem' + str(e),
            })

    return resend_otp_function
