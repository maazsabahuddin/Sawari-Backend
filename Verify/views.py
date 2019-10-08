from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.http import JsonResponse, HttpResponseForbidden
from django.shortcuts import redirect
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_encode
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import AllowAny
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST
from rest_framework.views import APIView

from rest_framework.authtoken.models import Token
from django.utils.encoding import force_bytes, force_text
from Verify.token_generator import account_activation_token
from .twilio_verify import send_verification_code, check_verification_code, check_email_verification, verify_user_otp
from .models import User, Customer
from django.core.mail import EmailMessage
import math, random


def generate_otp():
    digits = "0123456789"
    otp = ""
    for i in range(6):
        otp += digits[math.floor(random.random() * 10)]
    return otp


class VerifyCode(APIView):

    @method_decorator(csrf_exempt)
    def post(self, request):
        try:
            contact_number = request.POST['contact_number']
            verification_code = request.POST['v_code']

            verification = check_verification_code(contact_number, verification_code)

            if verification.status == "approved":
                return JsonResponse({'status': 'Perfect'})
            else:
                return JsonResponse({'status': 'Perfect2'})

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST
            })


class Register(APIView):

    permission_classes = (AllowAny, )

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
                return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Password Fields not matched'})

            if not email or not password:
                return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Email/Phone is required'})

            user_email = User.objects.filter(email=email).first()
            user_phone_no = User.objects.filter(phone_number=phone_number).first()

            if user_email or user_phone_no:
                return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Email/Phone already registered.'})

            with transaction.atomic():
                if email is not '' and phone_number is not '':
                    return JsonResponse({'status': HTTP_404_NOT_FOUND, 'message': 'Ruko abhi kuch krty hen...'})

                otp = generate_otp()
                if email is not '':
                    user = User.objects.create(
                        email=email,
                        password=make_password(password),
                        phone_number=None,
                        is_active=False,
                        is_verified=False,
                        otp=otp,
                    )
                    user.save()
                    Customer.objects.create(user=user)
                    if user:
                        token, _ = Token.objects.get_or_create(user=user)
                        # return JsonResponse({'status': HTTP_200_OK, })

                    mail_subject = 'Activate your account.'
                    message = {
                        'Email': user.email,
                        'OTP': otp,
                        # 'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        # 'token': account_activation_token.make_token(user),
                    }
                    content = {"%s: %s" % (key, value) for (key, value) in message.items()}
                    content = "\n".join(content)
                    to_email = email
                    send_email = EmailMessage(
                        mail_subject, content, to=[to_email]
                    )
                    send_email.send()
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'token': token.key,
                        'message': 'OTP has been successfully sent.',
                    })

                if phone_number is not '':
                    send_verification_code(phone_number)
                    user = User.objects.create(
                        email=None,
                        email_otp=None, # will be change soon as twilio ka masla hal hjae....
                        # otp=otp,
                        password=make_password(password),
                        phone_number=phone_number,
                        is_verified=False,
                        is_active=False,
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

