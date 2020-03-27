# #
# #
# #
# # # Driver code
# # if __name__ == "__main__":
# #     print("OTP of 4 digits:", generate_otp())
#
#
# # from twilio.rest import Client
# #
# #
# # # Your Account Sid and Auth Token from twilio.com/console
# # # DANGER! This is insecure. See http://twil.io/secure
# # account_sid = 'ACc2d21586f29d9728eb8be6b7f7cbab17'
# # auth_token = '6b978d120ab33f30ce16ee4e275df2f9'
# # client = Client(account_sid, auth_token)
# #
# # message = client.messages \
# #     .create(
# #          body='Hello ',
# #          from_='+12068097984',
# #          to='+923412381648'
# #      )
# #
# # print(message.sid)
#
# # Checking formula
# # price_per_km = 5.5
# # kilometer = 20
# # service_fee = 10
# # amount = price_per_km * kilometer
# # service_fee_amount = (service_fee / 100) * amount
# #
# # print(amount)
# # print(round(amount + service_fee_amount))
# # from datetime import date
# #
# # import datetime
# #
# # time_now = datetime.datetime.today()
# # time_end = time_now + datetime.timedelta(0, 60)
# #
# # print(datetime.datetime.today())
# # print(time_end)
#
# # print(today())
# # print(today.month)
# # print(today.year)
# #
# #
# # class Res:
# #     prefix = "RES"
# #     dash = "-"
# #     today = datetime.date.today()
# #     reservation_no = ["RES-000001-102019", "RES-000002-102019"]
# #
# #     def generate_reservation_number(self):
# #         # creating a list of last reservation number to extract the resrvation number.
# #         last_value = self.last_value_res_no(self.reservation_no)
# #         res_no = int(last_value) + 1
# #         new_res_no = self.length_res_no(str(res_no))
# #         notation = self.prefix + self.dash + str(new_res_no) + self.dash + str(today.month) + str(today.year)
# #         self.reservation_no.append(notation)
# #         # word = self.prefix + res_no +
# #
# #     def last_value_res_no(self, list):
# #         value = list[-1]
# #         reservation_no = value.split('-')
# #         return reservation_no[1]
# #         # return actual_value
# #
# #     def length_res_no(self, res_no):
# #         return res_no.zfill(6)
# #
# #     def display(self):
# #         print(self.reservation_no)
# #
# #
# # obj = Res()
# # obj.generate_reservation_number()
# # obj.display()
#
# # a = ["ABC-000001-1019", "ABC-000002-1019"]
# # last_value = a[-1]
# # last_value_list = last_value.split('-')
# # actual_value = last_value_list[1]
# # print(actual_value)
#
#
# # a = "45"
# # b = a.zfill(6)
# # print(b)
#
#
# # import pytz, datetime
# # from A.settings import TIME_ZONE
#
# # local_tz = pytz.timezone(TIME_ZONE)
#
# # print(local_tz)
#
# # local_datetime = local_tz.localize(datetime.datetime.today())
#
# # print(local_datetime)
#
# # utc_datetime = local_datetime.astimezone(pytz.utc)
#
# # print(utc_datetime)
#
#
# # def utc_to_local(utc_dt):
# #     local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
# #     return local_tz.normalize(local_dt)
# #
# #
# # print(local_datetime)
# # print(utc_datetime)
# # print(utc_to_local(utc_datetime))
#
# # class A(object):
# #     def foo(self, x):
# #         print("executing foo(%s, %s)" % (self, x))
# #
# #     @classmethod
# #     def class_foo(cls, x):
# #         print("executing class_foo(%s, %s)" % (cls, x))
# #
# #     @staticmethod
# #     def static_foo(x):
# #         print("executing static_foo(%s)" % x)
# #
# #
# # a = A()
# # # a.foo(1)
# # # a.class_foo(1)
# # # a.static_foo(1)
# # A.static_foo(1)
#
#
# # a = ''
# # if a:
# #     print("Yes")
# # else:
# #     print('No')
#
#
# # a = 'False'
# # if not a:
# #     print("WOW")
#
# # decorators 1
# # def hello_function(func):
# #
# #     def hello():
# #         print("Hello1")
# #         func()
# #     return hello
# #
# #
# # def function_to_be_used():
# #     print("Hii ! ")
# #
# #
# # obj = hello_function(function_to_be_used)
# # obj()
#
#
# # decorators 2
# import time
# import math
#
#
# # def decorator(func):
# #
# #     def inner_func(*args, **kwargs):
# #
# #         sum = base_func(*args, **kwargs)
# #         return sum
# #
# #     def base_func(*args, **kwargs):
# #         return 2
# #
# #     return inner_func
# #
# #
# # @decorator
# # def a():
# #     pass
# #
# #
# # print("Decorator is: ", a())
#
#
# # import uuid
# # print(uuid.uuid4())
# # print(uuid.uuid1())
#
# # regex
# # import re
# #
# # from A.settings import COUNTRY_CODE_PK
# #
# # txt = "maazsabahuddin@gmail.com"
# # EMAIL_REGEX = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
# # if txt:
# #     x = re.search(EMAIL_REGEX, txt)
# #
# #     if x:
# #         print("Correct Email")
# #
# #
# # phonenumber= "+923442713545"
# #
# # regex = r"\+"+COUNTRY_CODE_PK+r"\d{10}"
# # print(regex)
# #
# # if re.search(regex, phonenumber):
# #     print("Valid phone number")
# # else:
# #     print("Invalid phone number")
#
#
# # class Base:
# #
# #     def __init__(self):
# #         self.a = 199
# #
# #
# # class Derive(Base):
# #
# #     def __init__(self):
# #         Base.__init__(self)
# #         print(self.a)
# #
# #
# # z = Derive()
#
#
# class Foo:
#
#     def __init__(self):
#         raise ValueError("Error")
#
#     @staticmethod
#     def foo():
#         print("foo")
#
#
# Foo.foo()
#
#

# email = 'maazsabahuddin@gmail.com'
# first_name = email.split('@')
# print(first_name[0])
#
#
# def distance_formula(lat1, lon1, lat2, lon2):
#     p = 0.017453292519943295
#     a = 0.5 - cos((lat2-lat1)*p)/2 + cos(lat1*p)*cos(lat2*p) * (1-cos((lon2-lon1)*p)) / 2
#     return 12742 * asin(sqrt(a))
#
#
# print(distance_formula(24.907026, 67.112126, 24.821317, 67.034179))


# import requests, json
# 
# 
# def catch_distance_time(start_lat, start_lon, stop_lat, stop_lon):
# 
#     distance_matrix_api_url = 'https://maps.googleapis.com/maps/api/distancematrix/json?'
# 
#     map_data = requests.get(distance_matrix_api_url + 'origins={},{}'.format(start_lat, start_lon) +
#                             '&destinations={},{}'.format(stop_lat, stop_lon) +
#                             '&key={}'.format(GOOGLE_API_KEY))
# 
#     a = map_data.json()
#     elements = a['rows'][0].get('elements')
#     _list_distance = elements[0].get('distance')
#     _list_duration = elements[0].get('duration')
# 
#     distance = _list_distance['text']
#     duration = _list_duration['text']
# 
#     duration_and_distance = {'distance': distance, 'duration': duration}
# 
#     return duration_and_distance
# 
# 
# print(catch_distance_time(24.907026, 67.112126, 24.821317, 67.034179))
# 

# z = [
#     {'element': [1, 2, 3, 5]},
# ]
#
# print(z[0].get('element'))
"""

name = "maazsabahuddin@gmail.com"

a = name.split('@')[0]
print(a)

"""

# import datetime
#
# time_now = datetime.datetime.today()
# print(time_now.date())
# print(time_now.time())

# a = 'Maaz'
# a.isdigit()

import inspect

# def f1():
#     f2()
#
#
# def f2():
#     print('caller name:', inspect.stack()[1][3])
#     print('caller name:', inspect.stack()[1].function)
#     print()
#
#
# f1()


#
# a = 1
# b = +1
# c = a+b
# print(c)


# a = 'maazsabahuddin@gmail.com '
# # a = a.strip()
# print(len(a))

# from datetime import datetime
# curr_time = datetime.now().time()
# print(curr_time)
# curr_time_plus = curr_time + datetime.timedelta()


# a = 'RES-000001-22020'
# # b = a.replace('-', '')
# c = a.replace('RES-', '').replace('-', '')
# print(c)


# a = {
#     'loc': {'a': 1, 'b': 2}
# }
#
# c = a.get('loc').get('a')
# print(c)

# a = [1, 2, 3]
# b = [2, 3]
#
# result = all(values in a for values in b)
# print(result)


"""

# importing the requests library
import requests

# api-endpoint
URL = "http://djangoworld.com/calculate/fare/"

# # location given here
# location = "delhi technological university"

# defining a params dict for the parameters to be sent to the API
PARAMS = {'total_seats': 2, 'kilometer': 13.3}
TOKEN = {'Authorization': 'd213aa54e1b4aec003d3c8db9bb4952ef487b221'}

# sending get request and saving the response as response object
r = requests.get(url=URL, params=PARAMS, headers=TOKEN)

# extracting data in json format
data = r.json()


# extracting latitude, longitude and formatted address
# of the first matching location
# latitude = data['results'][0]['geometry']['location']['lat']
# longitude = data['results'][0]['geometry']['location']['lng']
# formatted_address = data['results'][0]['formatted_address']
a = 10
# printing the output
# print("Latitude:%s\nLongitude:%s\nFormatted Address:%s"
# 	%(latitude, longitude,formatted_address))

"""

# a = '3442713545'
#
# if a[0] == ('0' or '+'):
#     print("Invalid number")

# a = ""
# b = ""
#
# if not (a or b):
#     print("True")
#


import re

phonenumber = "+923442713545asdada"
regex = r"\+" + "92" + r"3\d{9}"

if len(phonenumber) != 13:
    print("Invalid")