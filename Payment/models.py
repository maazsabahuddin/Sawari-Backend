from django.db import models
from django.utils import timezone
from User.models import User


class PaymentMethod(models.Model):
    objects = None
    # Auth-User added for check payment method Updating details details by a particular admin-user
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)  # Do ask Hammad bhai
    payment_method = models.CharField(max_length=50, unique=True)
    service_fee = models.FloatField(max_length=4)

    def __str__(self):
        return "{}".format(self.payment_method)


class Pricing(models.Model):
    objects = None
    # Auth-User added for check pricing Updating details by a particular admin-user
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    price_per_km = models.FloatField(blank=False, null=False, max_length=5)
    fixed_fare = models.FloatField(blank=False, null=False, max_length=5)
    updated_timestamp = models.DateTimeField(default=timezone.localtime(timezone.now()))

    def __str__(self):
        return "{} - {}".format(self.user_id, self.price_per_km)
