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
# from datetime import date
#
# import datetime
#
# time_now = datetime.datetime.today()
# time_end = time_now + datetime.timedelta(0, 60)
#
# print(datetime.datetime.today())
# print(time_end)

# print(today())
# print(today.month)
# print(today.year)
#
#
# class Res:
#     prefix = "RES"
#     dash = "-"
#     today = datetime.date.today()
#     reservation_no = ["RES-000001-102019", "RES-000002-102019"]
#
#     def generate_reservation_number(self):
#         # creating a list of last reservation number to extract the resrvation number.
#         last_value = self.last_value_res_no(self.reservation_no)
#         res_no = int(last_value) + 1
#         new_res_no = self.length_res_no(str(res_no))
#         notation = self.prefix + self.dash + str(new_res_no) + self.dash + str(today.month) + str(today.year)
#         self.reservation_no.append(notation)
#         # word = self.prefix + res_no +
#
#     def last_value_res_no(self, list):
#         value = list[-1]
#         reservation_no = value.split('-')
#         return reservation_no[1]
#         # return actual_value
#
#     def length_res_no(self, res_no):
#         return res_no.zfill(6)
#
#     def display(self):
#         print(self.reservation_no)
#
#
# obj = Res()
# obj.generate_reservation_number()
# obj.display()

# a = ["ABC-000001-1019", "ABC-000002-1019"]
# last_value = a[-1]
# last_value_list = last_value.split('-')
# actual_value = last_value_list[1]
# print(actual_value)


# a = "45"
# b = a.zfill(6)
# print(b)


# import pytz, datetime
# from A.settings import TIME_ZONE

# local_tz = pytz.timezone(TIME_ZONE)

# print(local_tz)

# local_datetime = local_tz.localize(datetime.datetime.today())

# print(local_datetime)

# utc_datetime = local_datetime.astimezone(pytz.utc)

# print(utc_datetime)


# def utc_to_local(utc_dt):
#     local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
#     return local_tz.normalize(local_dt)
#
#
# print(local_datetime)
# print(utc_datetime)
# print(utc_to_local(utc_datetime))

# class A(object):
#     def foo(self, x):
#         print("executing foo(%s, %s)" % (self, x))
#
#     @classmethod
#     def class_foo(cls, x):
#         print("executing class_foo(%s, %s)" % (cls, x))
#
#     @staticmethod
#     def static_foo(x):
#         print("executing static_foo(%s)" % x)
#
#
# a = A()
# # a.foo(1)
# # a.class_foo(1)
# # a.static_foo(1)
# A.static_foo(1)


# a = ''
# if a:
#     print("Yes")
# else:
#     print('No')


# a = 'False'
# if not a:
#     print("WOW")

# decorators 1
# def hello_function(func):
#
#     def hello():
#         print("Hello1")
#         func()
#     return hello
#
#
# def function_to_be_used():
#     print("Hii ! ")
#
#
# obj = hello_function(function_to_be_used)
# obj()


# decorators 2
import time
import math


# def decorator(func):
#
#     def inner_func(*args, **kwargs):
#
#         sum = base_func(*args, **kwargs)
#         return sum
#
#     def base_func(*args, **kwargs):
#         return 2
#
#     return inner_func
#
#
# @decorator
# def a():
#     pass
#
#
# print("Decorator is: ", a())


# import uuid
# print(uuid.uuid4())
# print(uuid.uuid1())

