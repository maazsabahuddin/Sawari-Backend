from functools import wraps
from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_400_BAD_REQUEST

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

            user = Token.objects.filter(key=token).first()
            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Token.',
                })

            return f(user, request)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem',
            })

    return decorated_function


def password_decorator(f):

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

            return f(user, request)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server problem',
            })

    return match_uuid
