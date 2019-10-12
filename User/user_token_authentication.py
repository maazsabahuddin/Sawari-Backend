from rest_framework.authtoken.models import Token


# Put those methods in mixin which can be used through out..
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
