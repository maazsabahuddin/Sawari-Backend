from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext_lazy as _


class User(AbstractUser):
    username = models.CharField(blank=True, null=True, max_length=60)
    phone_number = models.CharField(unique=True, max_length=15, null=True, blank=True)
    email = models.EmailField(_('email address'), unique=True, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    otp = models.CharField(default=None, max_length=8, null=True, blank=True)
    # is_email_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['username', 'password']

    def __str__(self):
        return "{} - {}".format(self.email, self.phone_number)


class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer')
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{} - {}".format(self.id, self.user.email)


class Captain(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='captain_id')
    vendor = models.ForeignKey('user', on_delete=models.CASCADE, blank=True, null=True, related_name='vendor_id')
    is_owner = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{} - {}".format(self.id, self.user.email)


class Vehicle(models.Model):
    vehicle_no_plate = models.CharField(blank=False, max_length=10)
    driver_ids = models.ManyToManyField(Captain, related_name='drivers', blank=True)
    owner = models.ForeignKey(Captain, on_delete=models.CASCADE)
    brand = models.CharField(blank=True, max_length=20)
    max_seats = models.IntegerField(blank=False)
    from_loc = models.CharField(max_length=255, default="K")
    to_loc = models.CharField(max_length=255, default="L")

    def __str__(self):
        return "Vehicle {} - {}".format(self.id, self.vehicle_no_plate)


class Ride(models.Model):
    driver_ids = models.ManyToManyField(Captain)
    vehicle_id = models.ForeignKey(to='Vehicle', on_delete=models.CASCADE, related_name='driver_vehicle')
    start_time = models.DateTimeField(blank=True, null=True)
    end_time = models.DateTimeField(blank=True, null=True)
    route = models.CharField(blank=False, max_length=256)
    seats_left = models.IntegerField(blank=False, null=False)

    def __str__(self):
        return "Ride {} - {}".format(self.id, self.vehicle_id.vehicle_no_plate)


class Reservation(models.Model):
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)
    ride_id = models.ForeignKey(Ride, on_delete=models.CASCADE)
    reservation_seats = models.IntegerField(blank=False)
    is_confirmed = models.BooleanField(default=False)
    # reservation_timestamp = models.DateTimeField(auto_now_add=True)
    # updated_timestamp = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return "{} - {}".format(self.id, self.customer_id.user.email)


class PaymentMethod(models.Model):
    payment_method = models.CharField(max_length=50, unique=True)
    service_fee = models.CharField(max_length=4)

    def __str__(self):
        return "{}".format(self.payment_method)


class Pricing(models.Model):
    price_per_km = models.CharField(blank=False, null=False, max_length=5)
    updated_timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{}".format(self.price_per_km)


class UserRideDetail(models.Model):
    ride_id = models.ForeignKey(Ride, on_delete=models.CASCADE)
    reservation_id = models.ForeignKey(Reservation, on_delete=models.CASCADE) # Must be many2manyfield do check that
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)
    kilometer = models.IntegerField(blank=False)
    price_per_km = models.CharField(blank=False, null=False, max_length=5)
    payment_method_id = models.ForeignKey(PaymentMethod, on_delete=models.CASCADE, blank=True, null=True)
    payment_status = models.BooleanField(default=False)
    total_payment = models.IntegerField(blank=False)
    pick_up_point = models.CharField(blank=True, max_length=256)
    drop_up_point = models.CharField(blank=True, max_length=256)
    ride_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return "{}".format(self.ride_id)

# from django.conf import settings
# from django.db.models.signals import post_save
# from django.dispatch import receiver
# from rest_framework.authtoken.models import Token
#
#
# @receiver(post_save, sender=settings.AUTH_USER_MODEL)
# def create_auth_token(sender, instance=None, created=False, **kwargs):
#     if created:
#         Token.objects.create(user=instance)

