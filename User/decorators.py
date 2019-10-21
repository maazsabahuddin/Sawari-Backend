from django.http import JsonResponse
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_200_OK, HTTP_400_BAD_REQUEST
from functools import wraps


def login_decorator(f):

    def decorated_function(*args):
        try:
            request = args[1]
            token = request.headers.get('authorization')

            if not token:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Token required for verification.',
                })

            user = Token.objects.filter(key=token).first()
            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid Token.',
                })

            return f(user, request)

        except Exception as e:
            return False

    return decorated_function
