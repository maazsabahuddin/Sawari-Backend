from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    username = models.CharField(blank=True, null=True, max_length=60)
    phone_number = models.CharField(default=None, unique=True, max_length=15, null=False, blank=False)
    email = models.EmailField(default=None, unique=True, null=True, blank=True)
    is_customer = models.BooleanField(default=False)
    is_captain = models.BooleanField(default=False)

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['username', 'password', 'email']

    def __str__(self):
        return "{} - {}".format(self.email, self.phone_number)


class UserOtp(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_otp')
    otp = models.CharField(default=None, max_length=8, null=True, blank=False)
    otp_time = models.DateTimeField(null=False, blank=False)
    otp_counter = models.IntegerField(null=False, blank=False, default=0)
    is_verified = models.BooleanField(default=False)
    password_reset_id = models.CharField(unique=True, null=True, blank=True, max_length=255)

    def __str__(self):
        return "{} - {} - {}".format(self.user.email, self.user.phone_number, self.is_verified)


class Customer(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='customer')
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{} - {} - {}".format(self.id, self.user.email, self.user.phone_number)


class Captain(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='captain_id')
    vendor = models.ForeignKey('user', on_delete=models.CASCADE, blank=True, null=True, related_name='vendor_id')
    is_owner = models.BooleanField(default=False)
    created_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{} - {}".format(self.id, self.user.email)


# Issey acha method hay decorator k through krlu.

# class SingletonModel(models.Model):
#     class Meta:
#         abstract = True
#
#     def save(self, *args, **kwargs):
#         self.pk = 1
#         super(SingletonModel, self).save(*args, **kwargs)
#
#     def delete(self, *args, **kwargs):
#         pass
#
#     @classmethod
#     def load(cls):
#         obj, created = cls.objects.get_or_create(pk=1)
#         return obj
#
#
# class SiteSettings(SingletonModel):
#     support = models.EmailField(default='supprot@example.com')

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

