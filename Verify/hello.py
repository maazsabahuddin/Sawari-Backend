#
#
#
# # Driver code
# if __name__ == "__main__":
#     print("OTP of 4 digits:", generate_otp())


# from twilio.rest import Client
#
#
# # Your Account Sid and Auth Token from twilio.com/console
# # DANGER! This is insecure. See http://twil.io/secure
# account_sid = 'ACc2d21586f29d9728eb8be6b7f7cbab17'
# auth_token = '6b978d120ab33f30ce16ee4e275df2f9'
# client = Client(account_sid, auth_token)
#
# message = client.messages \
#     .create(
#          body='Hello ',
#          from_='+12068097984',
#          to='+923412381648'
#      )
#
# print(message.sid)