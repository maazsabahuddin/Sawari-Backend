from django.db.models import Q
from django.contrib.auth import get_user_model

MyUser = get_user_model()


class CustomAuthenticationBackend(object):

    def authenticate(email_or_phone=None, password=None):
        try:
            user = MyUser.objects.get(
                 Q(email=email_or_phone) | Q(phone_number=email_or_phone)
            )
            if user.check_password(password):
                return user

        except MyUser.DoesNotExist:
            # MyUser().set_password(password)
            return None

    # def get_user(self, user_id):
    #     my_user_model = get_user_model()
    #     try:
    #         return my_user_model.objects.get(pk=user_id)
    #     except my_user_model.DoesNotExist:
    #         return None
