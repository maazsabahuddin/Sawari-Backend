from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


class User(AbstractUser):
    username = models.CharField(blank=True, null=True, max_length=60)
    phone_number = models.CharField(default=None, unique=True, max_length=15, null=True, blank=True)
    email = models.CharField(default=None, unique=True, max_length=255, null=True, blank=True)
    is_customer = models.BooleanField(default=False)
    is_captain = models.BooleanField(default=False)

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['username', 'password', 'email']

    def __str__(self):
        return "{} - {}".format(self.email, self.phone_number)


class UserOtp(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_otp')
    otp = models.CharField(default=None, max_length=8, null=True, blank=False)
    otp_time = models.DateTimeField(null=False, blank=False, default=timezone.localtime(timezone.now()))
    otp_counter = models.IntegerField(null=False, blank=False, default=0)
    is_verified = models.BooleanField(default=False)
    password_reset_id = models.CharField(unique=True, null=True, blank=True, max_length=255)

    def __str__(self):
        return "{} - {} - {}".format(self.user.email, self.user.phone_number, self.is_verified)

    # def from_db_value(self, value, expression, connection, context):
    #     if value is None:
    #         return None
    #     else:
    #         return django.utils.timezone.localtime(value)


class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer')
    created_date = models.DateTimeField(default=timezone.localtime(timezone.now()))

    def __str__(self):
        return "{} - {} - {}".format(self.id, self.user.email, self.user.phone_number)


class Captain(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='captain_id')
    vendor = models.ForeignKey('user', on_delete=models.CASCADE, blank=True, null=True, related_name='vendor_id')
    is_owner = models.BooleanField(default=False)
    created_date = models.DateTimeField(default=timezone.localtime(timezone.now()))

    def __str__(self):
        return "{} - {}".format(self.id, self.user.email)


class PlaceDetail(models.Model):
    place_id = models.CharField(max_length=50, blank=False, null=False, unique=True)
    place_name = models.CharField(max_length=100, blank=False, null=False)
    latitude = models.CharField(max_length=30, blank=False, null=False)
    longitude = models.CharField(max_length=30, blank=False, null=False)
    updated_date = models.DateTimeField(default=timezone.localtime(timezone.now()))

    def __str__(self):
        return "{} - {}".format(self.place_id, self.place_name)


class Place(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_place')
    place_id = models.ForeignKey(PlaceDetail, on_delete=models.CASCADE)
    place_type = models.CharField(max_length=10, blank=False)

    def __str__(self):
        return "{} - {} - {}".format(self.user, self.place_type, self.place_id.place_id)

