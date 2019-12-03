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
