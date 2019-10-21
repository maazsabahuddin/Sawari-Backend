import datetime

import math
import random

import pytz

from A.settings import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, EMAIL_HOST_USER, TIME_ZONE, OTP_COUNTER_LIMIT, OTP_VALID_TIME
from django_twilio.client import Client
from .models import User, UserOtp
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


# def test_send_mail(mail, mail_subject, content, from_email, to_email):
#     # Use Django send_mail function to construct a message
#     # Note that you don't have to use this function at all.
#     # Any other way of sending an email in Django would work just fine.
#     mail.send_mail(
#         'Example subject here',
#         'Here is the message body.',
#         'from@example.com',
#         ['to@example.com']
#     )
#
#     # Now you can test delivery and email contents
#     assert len(mail.outbox) == 1, "Inbox is not empty"
#     assert mail.outbox[0].subject == mail_subject
#     assert mail.outbox[0].body == content
#     assert mail.outbox[0].from_email == from_email
#     assert mail.outbox[0].to == to_email


# def check_email_verification(email, otp):
#
#     user = User.objects.filter(email=email).first()
#     if user.email:
#         if str(user.email_otp) == otp:
#             return True
#     return False


local_tz = pytz.timezone(TIME_ZONE)


# db sey time utc format mae ata hay..
# yeh method usko local time mae convert krdega..
def utc_to_local(utc_dt):
    local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
    return local_tz.normalize(local_dt)


def verify_user_otp(user, otp, time_now):

    try:
        otp_user_obj = UserOtp.objects.filter(user=user).first()
        if not otp_user_obj:
            return False

        # adding timezone to local time.
        time_now_format = local_tz.localize(time_now)

        # db time.
        otp_send_time = otp_user_obj.otp_time
        otp_end_time = otp_send_time + datetime.timedelta(0, OTP_VALID_TIME)

        # convert db time utc to local time format
        otp_end_time_local = utc_to_local(otp_end_time)

        if otp_user_obj.otp_counter < OTP_COUNTER_LIMIT:
            if time_now_format < otp_end_time_local:
                if otp_user_obj.otp == otp:
                    otp_user_obj.otp_counter = 0
                    otp_user_obj.is_verified = True
                    otp_user_obj.save()
                    return True
            # else:
            #     otp_counter = otp_user_obj.otp_counter
            #     otp_counter += 1
            #     otp_user_obj.otp_counter = otp_counter
            #     return False

        return False

    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.info(e)
        return None


def generate_otp():
    try:
        digits = "0123456789"
        otp = ""
        for i in range(6):
            otp += digits[math.floor(random.random() * 10)]
        return otp

    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.info(e)
        return None

