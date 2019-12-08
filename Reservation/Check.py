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

# for ride in range(len(a)):
#     for key, values in a[ride].items():
#         if key == 'vehicle_no_plate' and values == 4.5:
#             stops = a[ride].get('stops')
#             print(stops)
#             break

# print(a)

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
