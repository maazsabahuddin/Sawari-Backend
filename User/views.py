import datetime

from rest_framework import generics

from CustomAuthentication.backend_authentication import CustomAuthenticationBackend, CustomUserCheck

from django.contrib.auth.hashers import make_password

from django.db import transaction
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from rest_framework.permissions import AllowAny
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token

from django_twilio.client import Client
from A.settings import TWILIO_AUTH_TOKEN, TWILIO_ACCOUNT_SID, OTP_INITIAL_COUNTER
from .otp_verify import verify_user_otp, generate_otp, send_otp_phone, send_otp_email
from .models import User, Customer, UserOtp
from .user_token_authentication import UserMixin
from .decorators import login_decorator


account_sid = TWILIO_ACCOUNT_SID
auth_token = TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)


class Register(APIView):
    permission_classes = (AllowAny,)

    @method_decorator(transaction.atomic, csrf_exempt)
    def post(self, request):
        try:
            data = request.data.get
            email = data('email')
            phone_number = data('phone_number')
            password = data('password')
            confirm_password = data('confirm_password')
            is_customer = data('is_customer')

            if email is None:
                email = ''

            if phone_number is None:
                phone_number = ''

            if not is_customer or is_customer == 'False':
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

            user_email = User.objects.filter(email=email).first()
            user_phone_no = User.objects.filter(phone_number=phone_number).first()

            if user_email or user_phone_no:
                return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Email/Phone already registered.'})

            with transaction.atomic():

                otp = generate_otp()
                if email and phone_number:

                    if not send_otp_email(email, otp):
                        return JsonResponse({
                            'status': HTTP_400_BAD_REQUEST,
                            'message': 'Invalid Email',
                        })

                    if not send_otp_phone(phone_number, otp):
                        return JsonResponse({
                            'status': HTTP_400_BAD_REQUEST,
                            'message': 'Invalid phone number',
                        })

                    user = User.objects.create(
                        email=email,
                        phone_number=phone_number,
                        password=make_password(password),
                        is_active=False,
                        is_customer=is_customer,
                    )
                    user_otp = UserOtp.objects.create(
                        user=user,
                        otp=otp,
                        opt_time=datetime.datetime.today(),
                        otp_counter=OTP_INITIAL_COUNTER,
                        is_verified=False,
                    )
                    user_otp.save()
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

                if email:

                    # Sending OTP Via Email
                    if not send_otp_email(email, otp):
                        return JsonResponse({
                            'status': HTTP_400_BAD_REQUEST,
                            'message': 'Invalid Email',
                        })

                    user = User.objects.create(
                        email=email,
                        password=make_password(password),
                        phone_number=None,
                        is_active=False,
                        is_customer=is_customer,
                    )
                    user_otp = UserOtp.objects.create(
                        user=user,
                        otp=otp,
                        opt_time=datetime.datetime.today(),
                        otp_counter=OTP_INITIAL_COUNTER,
                        is_verified=False,
                    )
                    user_otp.save()
                    user.save()

                    Customer.objects.create(user=user)
                    if user:
                        token, _ = Token.objects.get_or_create(user=user)

                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'token': token.key,
                        'message': 'OTP has been successfully sent.',
                    })

                if phone_number:
                    if not send_otp_phone(phone_number, otp):
                        return JsonResponse({
                            'status': HTTP_400_BAD_REQUEST,
                            'message': 'Invalid Phone Number',
                        })

                    user = User.objects.create(
                        email=None,
                        password=make_password(password),
                        phone_number=phone_number,
                        is_active=False,
                        is_customer=is_customer,
                    )
                    user_otp = UserOtp.objects.create(
                        user=user,
                        otp=otp,
                        otp_time=datetime.datetime.today(),
                        otp_counter=OTP_INITIAL_COUNTER,
                        is_verified=False,
                    )
                    user_otp.save()
                    user.save()
                    print(otp)

                    Customer.objects.create(user=user)
                    if user:
                        token, _ = Token.objects.get_or_create(user=user)

                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'token': token.key,
                        'message': 'OTP has been successfully sent.',
                        # 'otp_phone_sid': message.sid,
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
            token = request.data.get('token')
            otp = request.data.get('otp')

            token_obj = Token.objects.filter(key=token).first()

            if token_obj:
                if token_obj.user.is_active:
                    return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'Already Verified', })

                time_now = datetime.datetime.today()
                if verify_user_otp(token_obj.user, otp, time_now):
                    token_obj.user.is_active = True
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
    # permission_classes = (AllowAny,)

    def post(self, request):
        try:
            # print(request)
            email_or_phone = request.data.get("email_or_phone")
            password = request.data.get('password')
            # email_or_phone = request.POST['email_or_phone']

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

            if email_or_phone and password:
                user = CustomAuthenticationBackend.authenticate(email_or_phone, password)

                if user:
                    if not user.is_customer:
                        return JsonResponse({
                            'status': HTTP_400_BAD_REQUEST,
                            'message': 'Not a customer',
                        })
                    token, _ = Token.objects.get_or_create(user=user)
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'message': 'Login Successfully',
                        'token': token.key
                    })

            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': 'Invalid Credentials',
            })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server down',
            })


class UserLogout(generics.GenericAPIView):

    @login_decorator
    def post(self, request):
        try:
            user = self.user

            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid token'
                })

            user.auth_token.delete()
            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'Logged out',
            })
        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Error.'
            })


class UserResendOtp(UserMixin, generics.GenericAPIView):

    @method_decorator(transaction.atomic, login_decorator)
    def post(self, request):
        try:
            user = self.user

            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid token'
                })

            email = user.email
            phone_number = user.phone_number

            if not email and not phone_number:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'User not registered.'
                })

            user_otp_obj = UserOtp.objects.filter(user=user).first()
            if not user_otp_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'User not found.',
                })

            with transaction.atomic():

                otp = generate_otp()
                if email and phone_number:
                    if not send_otp_email(email, otp):
                        return JsonResponse({
                            'status': HTTP_400_BAD_REQUEST,
                            'message': 'Invalid Email',
                        })

                    if not send_otp_phone(phone_number, otp):
                        return JsonResponse({
                            'status': HTTP_400_BAD_REQUEST,
                            'message': 'Invalid phone number',
                        })

                    self.user_otp_save(user_otp_obj, otp)

                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'message': 'OTP has been successfully sent.',
                    })

                if email:
                    if not send_otp_email(email, otp):
                        return JsonResponse({
                            'status': HTTP_400_BAD_REQUEST,
                            'message': 'Invalid Email',
                        })

                    self.user_otp_save(user_otp_obj, otp)

                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'message': 'OTP has been successfully sent.',
                    })

                if phone_number:
                    if not send_otp_phone(phone_number, otp):
                        return JsonResponse({
                            'status': HTTP_400_BAD_REQUEST,
                            'message': 'Invalid phone number',
                        })

                    if not self.user_otp_save(user_otp_obj, otp):
                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'message': 'User_otp model Error.',
                        })
                    print(otp)

                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'message': 'OTP has been successfully sent.',
                    })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class PasswordChange(generics.GenericAPIView):

    @login_decorator
    def post(self, request):
        try:
            user = self.user
            old_password = request.data.get('old_password')
            password = request.data.get('password')
            confirm_password = request.data.get('confirm_password')

            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No user found',
                })

            if not (old_password and password and confirm_password):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'All field are required.',
                })

            if password != confirm_password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Password Fields not matched.',
                })

            if password == old_password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'You cannot set old password as new password.',
                })

            if not user.check_password(old_password):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Old Password not matched.',
                })

            user.set_password(password)
            user.save()

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'Password has been changed.',
            })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


# Work in progress
class PasswordReset(UserMixin, generics.GenericAPIView):

    def post(self, request):
        try:
            email_or_phone = request.POST['email_or_phone']
            user = CustomUserCheck.check_user(email_or_phone)

            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No user found',
                })

            if not email_or_phone:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Email/Phone is required'
                })

            email = user.email
            phone_number = user.phone_number

            user_otp_obj = UserOtp.objects.filter(user=user).first()
            if not user_otp_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'User not found.',
                })

            with transaction.atomic():

                otp = generate_otp()
                if email and phone_number:
                    if send_otp_email(email, otp) and send_otp_phone(phone_number, otp):
                        self.user_otp_save(user_otp_obj, otp)
                        request.session['user'] = user
                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'message': 'OTP has been successfully sent.',
                        })
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Email/Phone',
                    })

                if email:
                    if send_otp_email(email, otp):
                        self.user_otp_save(user_otp_obj, otp)
                        request.session['user'] = user
                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'message': 'OTP has been successfully sent.',
                        })
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Email',
                    })

                if phone_number:
                    if send_otp_phone(phone_number, otp):
                        self.user_otp_save(user_otp_obj, otp)
                        request.session['user'] = user
                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'message': 'OTP has been successfully sent.',
                        })
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid phone number',
                    })
                    print(otp)

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


class PasswordResetCheck(generics.GenericAPIView):

    @method_decorator(transaction.atomic)
    def post(self, request):
        try:
            user = request.session['user']
            otp = request.POST['otp']
            password = request.POST['password']
            confirm_password = request.POST['confirm_password']

            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No user found',
                })

            if password != confirm_password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Password Fields not matched.',
                })

            if password == user.password:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'You cannot set old password as new password.',
                })

            with transaction.atomic():

                time_now = datetime.datetime.today()
                if not verify_user_otp(user, otp, time_now):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'OTP not matched.',
                    })

                user.set_password(password)
                user.is_active = True
                user.save()
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'Password successfully reset.',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server Error.',
            })
