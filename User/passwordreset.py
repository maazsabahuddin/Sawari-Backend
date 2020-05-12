import uuid

from django.contrib.auth.hashers import make_password
from django.http import JsonResponse
from rest_framework import generics
from urllib3.connection import log
from django import forms
import A
from A.settings.base import EMAIL_HOST_USER, NOT_CATCHABLE_ERROR_CODE, NOT_CATCHABLE_ERROR_MESSAGE, COUNTRY_CODE_PK, \
    OTP_COUNTER_LIMIT
from CustomAuthentication.backend_authentication import CustomUserCheck
from User.decorators import password_reset_decorator
from User.exceptions import MissingField, WrongPhonenumber, TwilioException, UserNotFound

import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from User.models import UserOtp


class ForgotPassword(generics.GenericAPIView):

    @staticmethod
    def send_password_reset_link(**kwargs):
        user = kwargs.get('user')
        me = A.settings.base.EMAIL_HOST_USER
        you = user.email

        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Password Reset Email - Sawari"
        msg['From'] = me
        msg['To'] = you

        password_reset_uuid = uuid.uuid4()
        from django.utils import timezone
        user_otp = UserOtp.objects.filter(user=user).first()
        if not user_otp:
            user_otp = UserOtp.objects.create(user=user)

        user_otp.password_reset_id = password_reset_uuid
        user_otp.otp_time = timezone.localtime(timezone.now())
        user_otp.save()

        # text = "Hi!\nHow are you?\nHere is the link you wanted:\nhttp://www.python.org"
        html = """\
        <html>
          <head></head>
          <body>
            <p>You\'re receiving this email because you requested a password reset for your user account at Sawari. 
                <br><br>Please go to the following page and set a new password: <br><br>
                <a href="http://127.0.0.1:8000/password/reset/?token_uuid={}">
                http://tucktech.ai/password_reset/{}/</a> <br><br>
                If it's not you then kindly ignore this email or 
                reach to us at contactus@sawari.ai or +923442713545 <br><br>
                Thanks for using Sawari! <br> <br>
                The Sawari Team :) 
            </p>
          </body>
        </html>
        """.format(password_reset_uuid, password_reset_uuid)

        part2 = MIMEText(html, 'html')
        msg.attach(part2)

        mail = smtplib.SMTP('smtp.gmail.com', 587)
        mail.ehlo()
        mail.starttls()

        mail.login(me, A.settings.base.EMAIL_HOST_PASSWORD)
        mail.sendmail(me, you, msg.as_string())
        mail.quit()
        return True

    @password_reset_decorator
    def post(self, request, data=None):
        try:
            user = data.get('user')

            sent_email = ForgotPassword.send_password_reset_link(user=user)
            if not sent_email:
                return JsonResponse({'status': 400, 'message': 'Email not sent. Check your email and try again.'})
            return JsonResponse({'status': 200,
                                 'message': 'Reset your password from the link sent to your email.'})

        except (WrongPhonenumber, MissingField, UserNotFound, TwilioException) as e:
            return JsonResponse({
                'status': e.status_code,
                'message': e.message,
            })


def find_users_and_send_email():
    from django.http import HttpRequest
    from django.contrib.auth.forms import PasswordResetForm
    from django.contrib.auth.models import User

    user = User.objects.filter(email='sabahuddinaijaz@gmail.com').first()
    try:
        if user.email:
            log.info("Sending email for to this email:", user.email)
            form = PasswordResetForm({'email': user.email})

            assert form.is_valid()
            request = HttpRequest()
            request.META['SERVER_NAME'] = 'help.mydomain.com'
            request.META['SERVER_PORT'] = '80'
            form.save(
                request=request,
                # use_https=True,
                from_email="maazsabahuddin@gmail.com",
                email_template_name='registration/password_reset_email.html')

    except Exception as e:
        log.info(e)


class PasswordResetDone(forms.Form):
    pass


class PasswordResetForm(forms.Form):
    password = forms.CharField(max_length=32, widget=forms.PasswordInput)
    confirm_password = forms.CharField(max_length=32, widget=forms.PasswordInput)

    def clean(self):
        cleaned_data = super(PasswordResetForm, self).clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if not password and not confirm_password:
            raise forms.ValidationError('Enter password!')
        if password != confirm_password:
            raise forms.ValidationError('Password fields not matched!')

