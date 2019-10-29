from django.db import models


class PaymentMethod(models.Model):
    payment_method = models.CharField(max_length=50, unique=True)
    service_fee = models.FloatField(max_length=4)

    def __str__(self):
        return "{}".format(self.payment_method)


class Pricing(models.Model):
    price_per_km = models.FloatField(blank=False, null=False, max_length=5)
    updated_timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{}".format(self.price_per_km)


