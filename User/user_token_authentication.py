from rest_framework.authtoken.models import Token


# Put those methods in mixin which can be used through out..
from User.models import Customer


class UserMixin(object):

    vehicle_no_plate = None
    req_seats = None
    pick_up_point = None
    drop_up_point = None
    kilometer = None

    def get_user_via_token(self, token):
        token_obj = Token.objects.filter(key=token).first()

        if token_obj:
            return token_obj.user
        return None

    # get customer from user model
    def get_customer(self, user):
        customer_obj = Customer.objects.filter(user=user).first()
        if customer_obj:
            return customer_obj
        return None
