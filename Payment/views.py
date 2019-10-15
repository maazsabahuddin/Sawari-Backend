from Payment.models import PaymentMethod


class PaymentMixin(object):

    def payment_method_fee(self, payment_method):
        payment_method_obj = PaymentMethod.objects.filter(payment_method=payment_method).first()
        if payment_method_obj:
            service_fee = payment_method_obj.service_fee
            return service_fee
        return None

    def check_payment_method(self, payment_method):
        payment_method_obj = PaymentMethod.objects.filter(payment_method=payment_method).first()
        if payment_method_obj:
            return payment_method_obj
        return None

    # def fare_price(self, price_per_km, kilometer):
    #     if price_per_km:
    #         amount = price_per_km * kilometer
    #         return round(amount)
    #     return None

    def fare_price_online(self, payment_method, price_per_km: float, kilometer: float):
        if payment_method:
            service_fee = self.payment_method_fee(payment_method)

            if price_per_km and kilometer:
                amount = price_per_km * kilometer

                if service_fee == 0:
                    return round(amount)

                service_fee_amount = (service_fee / 100) * amount
                return round(amount + service_fee_amount)
        return None

