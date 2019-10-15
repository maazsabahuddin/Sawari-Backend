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

# Checking formula
# price_per_km = 5.5
# kilometer = 20
# service_fee = 10
# amount = price_per_km * kilometer
# service_fee_amount = (service_fee / 100) * amount
#
# print(amount)
# print(round(amount + service_fee_amount))
from datetime import date

print(date.today())