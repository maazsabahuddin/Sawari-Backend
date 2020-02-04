from builtins import staticmethod

from django.http import JsonResponse
from rest_framework.status import HTTP_400_BAD_REQUEST

from A import ONLINE_PAYMENT, ONLINE_PAYMENT_FEE, FIXED_FARE, KILOMETER_FARE
from Payment.models import PaymentMethod
from Reservation.views import fare_object


class PaymentMixin(object):

    @staticmethod
    def payment_method_fee(payment_method):
        payment_method_obj = PaymentMethod.objects.filter(payment_method=payment_method).first()
        if payment_method_obj:
            service_fee = payment_method_obj.service_fee
            return service_fee
        return None

    def fare_price_online(self, **kwargs):

        payment_method = kwargs.get('')
        req_seats = kwargs.get('')
        kilometer = kwargs.get('')

        if not ONLINE_PAYMENT:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Online Payment not available.'
            })

        fare_object_price = fare_object(FIXED_FARE, KILOMETER_FARE)
        fare = fare_object_price(req_seats=req_seats, kilometer=kilometer)

        if ONLINE_PAYMENT_FEE:
            service_fee_percent = self.payment_method_fee(payment_method)

            if service_fee_percent == 0:
                return round(fare)

            service_fee_amount = (service_fee_percent / 100) * fare
            return round(fare + service_fee_amount)

        return None


# Will be furnished upon request.
