#
#
# list_ = [12, 13, 17, 21, 25, 7]
# latitude = 14
# new_list = []
#
# for i in range(len(list_)):
#     new_list.append(14 - list_[i])
#
# print(list_)
# print(new_list)
#
# for i in range(len(new_list)):
#     if 5 >= new_list[i] >= -5:
#         print(list_[i], end=' ')

# c = {}
# a = [
#     {'a': 1, 'b': 2},
#     {'z': 3},
# ]
# c.update({'a': 10})
# print(c)

"""
i = 1
b = 2
z = {
    # 1: [1, 2, 3],
    # 2: [],
}
# z.get(2).append(4)
# z.update({2: z.get(2).append(4)})

z.update({1: [1]})
if z.get(1):
    z.get(1).append(4)
else:
    z.update({1: [1]})

print(z)
"""

# for key in z.keys():
#     print(key)

# z[1].append(1)
# z[b] = [5]
# z[b].append(6)
# z[b].append(7)

# for key, values in z.items():
#     print(key, values)

# class A:
#     def __init__(self):
#         pass
#
#
# obj = A()
# print(obj)
from cmath import asin, sqrt, cos

"""

a = [
    {'vehicle_no_plate': 4.5, 'seats': 3},
    {'vehicle_no_plate': 465, 'seats': 30, 'stops': ['A', 'B', 'C', 'D']},
]
stops = a[0].get('stops')
if stops:
    stops.append('maaz')
else:
    a[0].update({'stops': ['hii']})
# srafay@foree.co
print(a[0])
"""

# for ride in range(len(a)):
#     for key, values in a[ride].items():
#         if key == 'vehicle_no_plate' and values == 4.5:
#             stops = a[ride].get('stops')
#             print(stops)
#             break

# print(a)

"""

a = {
    'pick-up-location': {'a': 1, 'b': 2},
}

x = a.get('pick-up-location')
if x:
    x.update()

print(a)


ggg = {
    'pick-up-location': {
        'Jauhar Chorangi': '2 mins',
        'Jauhar more': '5 mins',
    }
}

zz = ggg.get('pick-up-location')
"""

# from A.settings import gmaps
#
# origin1 = (24.923179, 67.137853)
# origin2 = (24.921906, 67.136459)
# origin3 = (24.921176, 67.135622)
# origin4 = (24.920027, 67.134249)
# destination1 = (24.833896, 67.033666)
#
# distance = gmaps.distance_matrix([origin1], [origin2], mode='driving')["rows"][0]["elements"][0]["distance"]["text"]
# # duration = gmaps.distance_matrix(origins, destination, mode='driving')["rows"][0]["elements"][0]["duration"]["text"]
# print(distance)

# Method
"""
from math import sin, cos, sqrt, atan2, radians

# approximate radius of earth in km
R = 6373.0

lat1 = radians(24.923179)
lon1 = radians(67.137853)
lat2 = radians(24.921906)
lon2 = radians(67.136459)

dlon = lon2 - lon1
dlat = lat2 - lat1

a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
c = 2 * atan2(sqrt(a), sqrt(1 - a))

distance = R * c

print(distance)
"""

# Method
"""
import mpu

# Point one
lat1 = 24.923179
lon1 = 67.137853

# Point two
lat2 = 24.921906
lon2 = 67.136459

# What you were looking for
dist = mpu.haversine_distance((lat1, lon1), (lat2, lon2))
print(dist)
"""

from geopy.distance import geodesic


origin = (24.923179, 67.137853)  # (latitude, longitude) don't confuse
dist = (24.921906, 67.136459)

print(geodesic(origin, dist).meters)  # 23576.805481751613
print(geodesic(origin, dist).kilometers)  # 23.576805481751613
print(geodesic(origin, dist).miles)


import numpy as np


def Haversine(lat1,lon1,lat2,lon2, **kwarg):
    """
    This uses the ‘haversine’ formula to calculate the great-circle distance between two points – that is,
    the shortest distance over the earth’s surface – giving an ‘as-the-crow-flies’ distance between the points
    (ignoring any hills they fly over, of course!).
    Haversine
    formula:    a = sin²(Δφ/2) + cos φ1 ⋅ cos φ2 ⋅ sin²(Δλ/2)
    c = 2 ⋅ atan2( √a, √(1−a) )
    d = R ⋅ c
    where   φ is latitude, λ is longitude, R is earth’s radius (mean radius = 6,371km);
    note that angles need to be in radians to pass to trig functions!
    """
    R = 6371.0088
    lat1,lon1,lat2,lon2 = map(np.radians, [lat1,lon1,lat2,lon2])

    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat/2)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon/2) **2
    c = 2 * np.arctan2(a**0.5, (1-a)**0.5)
    d = R * c
    return d


print(Haversine(24.923179, 67.137853, 24.921906, 67.136459))
