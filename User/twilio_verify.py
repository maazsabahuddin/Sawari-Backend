import math
import random

from A.settings import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, SENDER_PHONE_NUMBER
from A.settings import EMAIL_HOST_USER
from django_twilio.client import Client
from .models import User
from django.core.mail import EmailMessage

account_sid = TWILIO_ACCOUNT_SID
auth_token = TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)


def send_otp_phone(phone_number, otp):
    try:
        message_body = 'Dear Sawari User, your OTP code is: ' + str(otp)
        sender_phone_number = SENDER_PHONE_NUMBER

        message = client.messages.create(
            from_=sender_phone_number,
            body=message_body,
            to=phone_number,
         )
        return True

    except TypeError:
        return False


def send_otp_email(email, otp):
    try:
        from_email = EMAIL_HOST_USER
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
        # test_send_mail(send_email, mail_subject, content, from_email, to_email)
        return True

    except Exception as e:
        import logging
        logger = logging.info(__name__)
        logger.info(e)
        return False


def test_send_mail(mail, mail_subject, content, from_email, to_email):
    # Use Django send_mail function to construct a message
    # Note that you don't have to use this function at all.
    # Any other way of sending an email in Django would work just fine.
    mail.send_mail(
        'Example subject here',
        'Here is the message body.',
        'from@example.com',
        ['to@example.com']
    )

    # Now you can test delivery and email contents
    assert len(mail.outbox) == 1, "Inbox is not empty"
    assert mail.outbox[0].subject == mail_subject
    assert mail.outbox[0].body == content
    assert mail.outbox[0].from_email == from_email
    assert mail.outbox[0].to == to_email


# def check_email_verification(email, otp):
#
#     user = User.objects.filter(email=email).first()
#     if user.email:
#         if str(user.email_otp) == otp:
#             return True
#     return False
#
# def verify_user_otp(user, otp):
#     if user:
#         if user.otp == otp:
#             return True
#     return False
#
#
# def generate_otp():
#     digits = "0123456789"
#     otp = ""
#     for i in range(6):
#         otp += digits[math.floor(random.random() * 10)]
#     return otp
