from rest_framework.authtoken.models import Token
import datetime

# Put those methods in mixin which can be used through out..
from User.models import Customer, UserOtp


class UserMixin(object):

    @staticmethod
    def get_user_via_token(token):
        token_obj = Token.objects.filter(key=token).first()

        if token_obj:
            return token_obj.user
        return None

    # get customer from user model
    @staticmethod
    def get_customer(user):
        customer_obj = Customer.objects.filter(user=user).first()
        if customer_obj:
            return customer_obj
        return None

    @staticmethod
    def user_otp_save(user, otp):
        if user:
            otp_counter = user.otp_counter
            otp_counter += 1

            user.otp = otp
            user.otp_time = datetime.datetime.today()
            user.is_verified = False
            user.otp_counter = otp_counter
            user.save()
            return True

        return False

    @staticmethod
    def save_user_password_uuid(user, password_uuid):
        user_obj = UserOtp.objects.filter(user=user).first()
        if user_obj:
            user_obj.password_reset_id = password_uuid
            user_obj.save()
            return True
        return False

    @staticmethod
    def match_user_password_uuid(user, password_uuid):
        user_obj = UserOtp.objects.filter(user=user).first()
        if user_obj and user_obj.password_reset_id == password_uuid:
            return True
        return False
