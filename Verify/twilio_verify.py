import math
import random

from A.settings import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN
from django_twilio.client import Client
from .models import User

account_sid = TWILIO_ACCOUNT_SID
auth_token = TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)


def send_verification_code(contact_number):
    verification = client.verify \
        .services('VA0f87bb3e0cbe8bbc2e009b410c5bec3f') \
        .verifications \
        .create(to=contact_number, channel='sms')

    return verification


def check_verification_code(contact_number, code):

    verification_check = client.verify \
        .services('VA0f87bb3e0cbe8bbc2e009b410c5bec3f') \
        .verification_checks \
        .create(to=contact_number, code=code)
    return verification_check


def check_email_verification(email, otp):

    user = User.objects.filter(email=email).first()
    if user.email:
        if str(user.email_otp) == otp:
            return True
    return False


def verify_user_otp(user, otp):
    if user:
        if user.otp == otp:
            return True
    return False


def generate_otp():
    digits = "0123456789"
    otp = ""
    for i in range(6):
        otp += digits[math.floor(random.random() * 10)]
    return otp



