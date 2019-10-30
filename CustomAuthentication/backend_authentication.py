from django.db.models import Q
from django.contrib.auth import get_user_model

MyUser = get_user_model()


class CustomAuthenticationBackend(object):

    @staticmethod
    def authenticate(email_or_phone=None, password=None):
        try:
            user = MyUser.objects.get(
                 Q(email=email_or_phone) | Q(phone_number=email_or_phone)
            )
            if user.check_password(password):
                return user

        except MyUser.DoesNotExist:
            return None


class CustomUserCheck(object):

    @staticmethod
    def check_user(email_or_phone):
        try:
            user = MyUser.objects.get(
                Q(email=email_or_phone) | Q(phone_number=email_or_phone)
            )
            if user:
                return user
            return None

        except MyUser.DoesNotExist:
            return None

    @staticmethod
    def check_user_seperately(email, phone):
        try:
            user = MyUser.objects.get(
                Q(email=email) | Q(phone_number=phone)
            )
            if user:
                return user
            return None

        except MyUser.DoesNotExist:
            return None

