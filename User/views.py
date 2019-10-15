from django.contrib.auth import authenticate, logout
from django.views.decorators.cache import never_cache
from rest_framework import generics

from CustomAuthentication.backend_authentication import CustomAuthenticationBackend
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.http import JsonResponse, request
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import EmailMessage

from rest_framework.permissions import AllowAny
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token

from django_twilio.client import Client
from A.settings import TWILIO_AUTH_TOKEN, TWILIO_ACCOUNT_SID
from .twilio_verify import verify_user_otp, generate_otp, send_otp_phone, send_otp_email
from .models import User, Customer

account_sid = TWILIO_ACCOUNT_SID
auth_token = TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)


class Register(APIView):
    permission_classes = (AllowAny,)

    @method_decorator(transaction.atomic, csrf_exempt)
    def post(self, request):
        try:
            data = request.POST
            email = data['email']
            phone_number = data['phone_number']
            password = data['password']
            confirm_password = data['confirm_password']
            is_customer = data['is_customer']

            if password != confirm_password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Password Fields not matched'
                })

            if not email and not password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Email/Phone is required'
                })

            user_email = User.objects.filter(email=email).first()
            user_phone_no = User.objects.filter(phone_number=phone_number).first()

            if user_email or user_phone_no:
                return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Email/Phone already registered.'})

            with transaction.atomic():

                otp = generate_otp()
                if email is not '' and phone_number is not '':

                    send_otp_email(email, otp)
                    if send_otp_phone(phone_number, otp):

                        user = User.objects.create(
                            email=email,
                            phone_number=phone_number,
                            password=make_password(password),
                            is_active=False,
                            is_verified=False,
                            otp=otp,
                            is_customer=is_customer,
                        )
                        user.save()
                        Customer.objects.create(user=user)
                        if user:
                            token, _ = Token.objects.get_or_create(user=user)

                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'token': token.key,
                            'message': 'OTP has been successfully sent.',
                            # 'message_sid': message.sid,
                        })

                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Email',
                    })

                if email is not '':

                    # Sending OTP Via Email
                    if send_otp_email(email, otp):

                        user = User.objects.create(
                            email=email,
                            password=make_password(password),
                            phone_number=None,
                            is_active=False,
                            is_verified=False,
                            otp=otp,
                            is_customer=is_customer,
                        )
                        user.save()
                        Customer.objects.create(user=user)
                        if user:
                            token, _ = Token.objects.get_or_create(user=user)

                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'token': token.key,
                            'message': 'OTP has been successfully sent.',
                        })

                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Email',
                    })

                if phone_number is not '':
                    if send_otp_phone(phone_number, otp):
                        user = User.objects.create(
                            email=None,
                            otp=otp,
                            password=make_password(password),
                            phone_number=phone_number,
                            is_verified=False,
                            is_active=False,
                            is_customer=is_customer,
                        )
                        user.save()
                        Customer.objects.create(user=user)
                        if user:
                            token, _ = Token.objects.get_or_create(user=user)

                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'token': token.key,
                            'message': 'OTP has been successfully sent.',
                            # 'otp_phone_sid': message.sid,
                        })

                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Phone Number',
                    })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST
            })


# for contact number as well as for email..
class IsVerified(APIView):

    def post(self, request):
        try:
            token = request.POST['token']
            otp = request.POST['otp']

            token_obj = Token.objects.filter(key=token).first()

            if token_obj:
                if token_obj.user.is_active:
                    return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Already Verified', })

                if verify_user_otp(token_obj.user, otp):
                    token_obj.user.is_active = True
                    token_obj.user.is_verified = True
                    token_obj.user.save()

                    return JsonResponse({'status': HTTP_200_OK, 'message': 'Verified', })
                return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'OTP not matched.', })

            return JsonResponse({
                'message': 'User not found',
                'status': HTTP_404_NOT_FOUND,
            })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND
            })


class UserLogin(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        try:
            email_or_phone = request.POST['email_or_phone']
            password = request.POST['password']

            if password is None:
                return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Password required.'})

            if not email_or_phone:
                return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Email/Phone required.'})

            if email_or_phone and password:
                user = CustomAuthenticationBackend.authenticate(email_or_phone, password)
                if user:
                    token, _ = Token.objects.get_or_create(user=user)
                    return JsonResponse({'status': HTTP_200_OK, 'token': token.key})

            return JsonResponse({'status': HTTP_404_NOT_FOUND, 'message': 'Invalid Credentials'})

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Server down'})


class UserLogout(APIView):

    @method_decorator(login_required)
    def post(self, request):
        return self.logout_method(request)

    def logout_method(self, request):
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
            return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Invalid Token.'})

        logout(request)
        return JsonResponse({'success': 'Logged out'}, status=HTTP_200_OK)


