import datetime
import re
import uuid
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
from A.settings import TWILIO_AUTH_TOKEN, TWILIO_ACCOUNT_SID, OTP_INITIAL_COUNTER, EMAIL_REGEX, PHONE_NUMBER_REGEX
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

            # Checking Validation
            if email:
                x = re.search(EMAIL_REGEX, email)
                if not x:
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Email',
                    })

            # Checking Validation
            if phone_number:
                phone_number_validation = re.match(PHONE_NUMBER_REGEX, phone_number)
                if not phone_number_validation:
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Phone Number',
                    })

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

    def post(self, request):
        try:
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
                        'token': token.key,
                        'message': 'Login Successfully',
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

    @transaction.atomic
    def post(self, request):
        try:
            email = request.data.get('email')
            phone_number = request.data.get('phone_number')

            # Check user Via Email and Phones
            user = CustomUserCheck.check_user_seperately(email, phone_number)

            if not email and not phone_number:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Email/Phone is required'
                })

            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'User not found',
                })

            user_otp_obj = UserOtp.objects.filter(user=user).first()

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
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': "Server Error.",
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


class PasswordReset(UserMixin, generics.GenericAPIView):

    @transaction.atomic
    def post(self, request):
        try:
            email_or_phone = request.data.get('email_or_phone')
            user = CustomUserCheck.check_user(email_or_phone)

            if not email_or_phone:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Email/Phone is required'
                })

            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'User not found',
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
                print(otp)
                if email and phone_number:
                    if send_otp_email(email, otp) and send_otp_phone(phone_number, otp):
                        self.user_otp_save(user_otp_obj, otp)
                        # request.session['user'] = user
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
                        # request.session['user'] = user
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
                        # request.session['user'] = user
                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'message': 'OTP has been successfully sent.',
                        })
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid phone number',
                    })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })


# Sending password uuid with api for verification and saving it to db.
class PasswordResetCheck(UserMixin, generics.GenericAPIView):

    @method_decorator(transaction.atomic)
    def post(self, request):
        try:
            email_or_phone = request.data.get('email_or_phone')
            otp = request.data.get('otp')

            user = CustomUserCheck.check_user(email_or_phone)
            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No user found',
                })

            if not otp:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'OTP required.',
                })

            with transaction.atomic():

                time_now = datetime.datetime.today()
                if not verify_user_otp(user, otp, time_now):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'OTP not matched.',
                    })

                user_uuid = uuid.uuid4()
                if not self.save_user_password_reset_uuid(user, user_uuid):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'uuid problem.',
                    })

                user.is_active = True
                user.save()

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'password_reset_id': user_uuid,
                    'message': 'OTP Matched',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server Error.',
            })


class SetNewPassword(UserMixin, generics.GenericAPIView):

    @transaction.atomic
    def post(self, request):
        try:
            email_or_phone = request.data.get('email_or_phone')
            password_reset_id = request.data.get('password_reset_id')
            password = request.data.get('password')
            confirm_password = request.data.get('confirm_password')

            user = CustomUserCheck.check_user(email_or_phone)
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

            with transaction.atomic():

                if not self.match_user_password_reset_uuid(user, password_reset_id):
                    return JsonResponse({
                        'status': HTTP_404_NOT_FOUND,
                        'message': 'No user found',
                    })

                # Moving into UserOtp model then access the field user and then move to Auth user and get the password.
                # So user.user.password.
                if password == user.password:
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'You cannot set old password as new password.',
                    })

                user.set_password(password)
                user.is_active = True
                user.save()

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': "Password successfully reset.",
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': "Cannot change password.",
            })


class UpdateName(generics.GenericAPIView):

    @login_decorator
    @transaction.atomic
    def post(self, request):
        try:

            user = self.user
            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': "User not found.",
                })

            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name')

            with transaction.atomic():
                user.first_name = first_name
                user.last_name = last_name
                user.save()

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': "Successful",
                })

        except Exception:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': "Error Encountered.",
            })


# Pending
class ChangePhoneNumber(UserMixin, generics.GenericAPIView):

    @login_decorator
    @transaction.atomic
    def post(self, request):
        try:
            user = self.user
            phone_number = request.data.get('phone_number')

            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "User not found."
                })

            # Checking Validation
            if phone_number:
                phone_number_validation = re.match(PHONE_NUMBER_REGEX, phone_number)
                if not phone_number_validation:
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Phone Number',
                    })

            if not phone_number:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "Phone Number required."
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

            with transaction.atomic():
                otp = generate_otp()
                user_otp_obj = UserOtp.objects.filter(user=user).first()
                self.user_otp_save(user_otp_obj, otp)

                if not send_otp_phone(phone_number, otp):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Invalid Phone Number',
                    })

                print(otp)

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'OTP has been successfully sent.',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server Error.'
            })

