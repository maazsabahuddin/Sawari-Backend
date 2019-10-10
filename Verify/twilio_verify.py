import math
import random

from A.settings import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN
from django_twilio.client import Client
from .models import User
from django.core.mail import EmailMessage

account_sid = TWILIO_ACCOUNT_SID
auth_token = TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)


def send_otp_phone(phone_number, otp):
    try:
        message_body = 'Dear Instant Bus user, your OTP code is: ' + str(otp)
        sender_phone_number = '+12068097984'

        message = client.messages.create(
            from_=sender_phone_number,
            body=message_body,
            to=phone_number,
        )
        return True

    except Exception as e:
        import logging
        logger = logging.info(__name__)
        logger.info(e)
        return False


def send_otp_email(email, otp):
    try:
        mail_subject = 'Activate your account.'
        message = {
            'Email': email,
            'OTP': otp,
            # 'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            # 'token': account_activation_token.make_token(user),
        }
        content = {"%s: %s" % (key, value) for (key, value) in message.items()}
        content = "\n".join(content)
        to_email = email
        send_email = EmailMessage(
            mail_subject, content, to=[to_email]
        )
        send_email.send()
        return True

    except Exception as e:
        import logging
        logger = logging.info(__name__)
        logger.info(e)
        return False

# def check_verification_code(contact_number, code):
#
#     verification_check = client.verify \
#         .services('VA0f87bb3e0cbe8bbc2e009b410c5bec3f') \
#         .verification_checks \
#         .create(to=contact_number, code=code)
#     return verification_check


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



