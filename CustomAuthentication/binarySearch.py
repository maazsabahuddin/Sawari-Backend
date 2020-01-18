#
#
# array = [10, 20, 30, 40, 50, 60, 70]
#
#
# def binary_search(req_value):
#
#     first = 0
#     last = len(array) - 1
#
#     while first <= last:
#         mid = (first + last)//2
#
#         if array[mid] == req_value:
#             return mid
#         elif array[mid] < req_value:
#             first = mid + 1
#         else:
#             last = mid - 1
#
#     return -1
#
#
# print("Value found at index: {}".format(binary_search(30)))


n = 5
fact = 1

for i in range(1, n+1):
    fact = fact * i

print(fact)
