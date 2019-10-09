from django.contrib.auth import authenticate, logout
from CustomAuthentication.backend_authentication import CustomAuthenticationBackend
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import EmailMessage

from rest_framework.permissions import AllowAny
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token

from .twilio_verify import send_verification_code, verify_user_otp, generate_otp
from .models import User, Customer


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

    # @method_decorator()
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

    permission_classes = (AllowAny, )

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

    # object return hura hay user ka..
    # change should be mande.. said by maaz on 9th october 2019 12:35 AM
    # contact no k through b login huna chaiye.. because email is not mandatory
    # def authenticate_user(self, email_or_phone, password):
    #
    #     user = CustomAuthenticationBackend.authenticate(email_or_phone, password)
    #     if user:
    #         return user
    #     return False


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
