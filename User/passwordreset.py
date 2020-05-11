from django.http import JsonResponse
from rest_framework import generics
from urllib3.connection import log

import A
from A.settings.base import EMAIL_HOST_USER, NOT_CATCHABLE_ERROR_CODE, NOT_CATCHABLE_ERROR_MESSAGE, COUNTRY_CODE_PK
from CustomAuthentication.backend_authentication import CustomUserCheck
from User.exceptions import MissingField, WrongPhonenumber, TwilioException, UserNotFound

import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class ForgotPassword(generics.GenericAPIView):

    @staticmethod
    def abc(**kwargs):
        user = kwargs.get('user')
        me = A.settings.base.EMAIL_HOST_USER
        you = user.email

        # Create message container - the correct MIME type is multipart/alternative.
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Password Reset Email - Sawari"
        msg['From'] = me
        msg['To'] = you

        # Create the body of the message (a plain-text and an HTML version).
        # text = "Hi!\nHow are you?\nHere is the link you wanted:\nhttp://www.python.org"
        html = """\
        <html>
          <head></head>
          <body>
            <p>You\'re receiving this email because you requested a password reset for your user account at Sawari. 
                <br>Please go to the following link and set a new password: <br><br>
                <a href="http://127.0.0.1:8000/password_reset/">http://127.0.0.1:8000/password_reset/</a> <br><br>
                If it's not you then kindly reach to us at contactus@sawari.ai or +923442713545
            </p>
          </body>
        </html>
        """

        # Record the MIME types of both parts - text/plain and text/html.
        # part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')

        # Attach parts into message container.
        # According to RFC 2046, the last part of a multipart message, in this case
        # the HTML message, is best and preferred.
        # msg.attach(part1)
        msg.attach(part2)
        # Send the message via local SMTP server.
        mail = smtplib.SMTP('smtp.gmail.com', 587)

        mail.ehlo()

        mail.starttls()

        mail.login(me, A.settings.base.EMAIL_HOST_PASSWORD)
        mail.sendmail(me, you, msg.as_string())
        mail.quit()
        return True

    @staticmethod
    def email(**kwargs):
        user = kwargs.get('user')

        from mailer import Mailer
        from mailer import Message

        message = Message(From=A.settings.base.EMAIL_HOST_USER,
                          To=user.email)

        message.Subject = "Password Reset Email - Sawari"
        message.Body = "<p>You\'re receiving this email because you requested a password reset for your user ' \
                  'account at Sawari. \nPlease go to the following page and set a new password: \n"
        message.Html = """<a href="http://www.python.org">link</a> you wanted.</p>"""

        sender = Mailer('smtp.gmail.com', use_tls=True, usr='email', pwd='password')
        sender.send(message)

        # subject = 'Password Reset Email - Sawari'
        # message = 'You\'re receiving this email because you requested a password reset for your user ' \
        #           'account at Sawari.\nPlease go to the following page and choose a new password:\n'
        # email_from = A.settings.base.EMAIL_HOST_USER
        # recipient_list = user.email
        # send_mail(subject, message, email_from, recipient_list)
        return True

    def post(self, request, data=None):
        try:
            email_or_phone = request.data.get('email_or_phone')
            email_or_phone = email_or_phone.strip()

            if not email_or_phone:
                raise MissingField(status_code=400, message='Email/Phone required.')

            if email_or_phone[0] == "0":
                email_or_phone = "+" + COUNTRY_CODE_PK + email_or_phone[1:]

            if email_or_phone[0] == "+":
                from User.views_designpatterns import UserMixinMethods
                if len(email_or_phone) != 13 or not UserMixinMethods.validate_phone(email_or_phone):
                    raise WrongPhonenumber(status_code=400, message='Invalid Phonenumber')

            from User.views_designpatterns import UserMixinMethods
            if not UserMixinMethods.validate_email(email_or_phone):
                raise WrongPhonenumber(status_code=400, message='Invalid email address')

            # Check if user exist or not.
            user = CustomUserCheck.check_user(email_or_phone)
            if not user:
                raise UserNotFound(status_code=400, message='Invalid Email/Phone.')

            sent_email = ForgotPassword.abc(user=user)
            if not sent_email:
                return JsonResponse({'status': 400, 'message': 'Email not sent. Check your email and try again.'})
            return JsonResponse({'status': 200,
                                 'message': 'Reset your password from the given link sent to your email.'})

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
        # continue