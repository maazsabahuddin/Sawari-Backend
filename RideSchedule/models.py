import datetime

from django.db import models
from Payment.models import PaymentMethod
from User.models import User
from Reservation.models import Reservation, Ride


# Create your models here.
class UserRideDetail(models.Model):
    ride_id = models.ForeignKey(Ride, on_delete=models.CASCADE)
    reservation_id = models.ForeignKey(Reservation, on_delete=models.CASCADE)  # Must be many2manyfield do check that
    admin_id = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    kilometer = models.FloatField(blank=True, null=True)
    price_per_km = models.FloatField(blank=True, null=True, max_length=5)
    payment_method_id = models.ForeignKey(PaymentMethod, on_delete=models.CASCADE, blank=True, null=True)
    payment_status = models.BooleanField(default=False)
    fare = models.IntegerField(blank=False)
    fixed_fare = models.BooleanField(default=False)
    pick_up_point = models.CharField(blank=True, max_length=256)
    drop_up_point = models.CharField(blank=True, max_length=256)
    ride_date = models.DateField(default=datetime.datetime.today)

    def __str__(self):
        return "{} - {}".format(self.reservation_id, self.ride_id)
