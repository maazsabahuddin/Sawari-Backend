import datetime

import math
import random

import pytz

from A.settings.base import TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, EMAIL_HOST_USER, local_tz, OTP_COUNTER_LIMIT, \
    OTP_VALID_TIME, SENDER_PHONE_NUMBER

from django_twilio.client import Client
from .models import UserOtp
from django.core.mail import EmailMessage

from User.exceptions import TwilioEmailException

account_sid = TWILIO_ACCOUNT_SID
auth_token = TWILIO_AUTH_TOKEN
client = Client(account_sid, auth_token)


class UserOTPMixin(object):

    @staticmethod
    def send_otp_phone(phone_number, otp):
        try:
            message_body = 'Dear Sawaari user, your OTP code is: ' + str(otp)
            sender_phone_number = SENDER_PHONE_NUMBER

            client.messages.create(
                from_=sender_phone_number,
                body=message_body,
                to=phone_number,
            )

        except Exception as e:
            raise TwilioEmailException(status_code=101)

    @staticmethod
    def send_otp_email(email, otp):
        try:
            from_email = EMAIL_HOST_USER
            mail_subject = 'Verify your account.'
            message = {
                'Email': email,
                'OTP': otp,
            }
            content = {"%s: %s" % (key, value) for (key, value) in message.items()}
            content = "\n".join(content)
            to_email = email
            send_email = EmailMessage(
                mail_subject, content, to=[to_email]
            )
            send_email.send()

        except Exception as e:
            raise TwilioEmailException(status_code=102)

    # local_tz = pytz.timezone(TIME_ZONE)

    # db sey time utc format mae ata hay..
    # yeh method usko local time mae convert krdega..
    @classmethod
    def utc_to_local(cls, utc_dt):
        local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
        return local_tz.normalize(local_dt)

    @classmethod
    def verify_user_otp(cls, user, otp, time_now):

        try:
            otp_user_obj = UserOtp.objects.filter(user=user).first()
            if not otp_user_obj:
                return False

            # adding current timezone to local time.
            time_now_format = local_tz.localize(time_now)

            # fetch db time
            otp_send_time = otp_user_obj.otp_time

            # adding seconds to db time..s
            otp_end_time = otp_send_time + datetime.timedelta(0, OTP_VALID_TIME)

            # convert db time utc to local time format
            otp_end_time_local = cls.utc_to_local(otp_end_time)

            if otp_user_obj.otp_counter > OTP_COUNTER_LIMIT:
                return False

            if time_now_format > otp_end_time_local:
                return False

            if otp_user_obj.otp == otp:
                otp_user_obj.otp_counter = 0
                otp_user_obj.is_verified = True
                otp_user_obj.save()
                return True

            return False

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return None

    @staticmethod
    def generate_otp():
        try:
            digits = "0123456789"
            otp = ""
            for i in range(6):
                otp += digits[math.floor(random.random() * 10)]
            return otp

        except Exception as e:
            return None

    # @staticmethod
    # def password_reset_key():
    #     try:
    #         digits = "0123456789"
    #         otp = ""
    #         for i in range(6):
    #             otp += digits[math.floor(random.random() * 10)]
    #         return otp
    #
    #     except Exception as e:
    #         import logging
    #         logger = logging.getLogger(__name__)
    #         logger.info(e)
    #         return None
