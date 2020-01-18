
# class Singleton:
#
#     __instance = None
#
#     @staticmethod
#     def getInstance():
#         """ Static access method. """
#         if Singleton.__instance is None:
#             Singleton()
#         return Singleton.__instance
#
#     def __init__(self):
#         """ Virtually private constructor. """
#         if Singleton.__instance is not None:
#             raise Exception("This class is a singleton!")
#         else:
#             Singleton.__instance = self
#
#
# # s = Singleton()
# # print(s)
#
# # z = Singleton()
# # print(z)
#
# a = Singleton.getInstance()
# print(a)


# class A:
#
#     __instance = None
#
#     def __init__(self):
#         if A.__instance is not None:
#             raise Exception("This class is a singleton!")
#         else:
#             A.__instance = self
#
#     @staticmethod
#     def hello():
#         if A.__instance is None:
#             A()
#         print("This is a hello method.")
#         return A.__instance
#
#
# obj2 = A()
# print(obj2)
#
# obj1 = A.hello()
# print(obj1)


class B:

    def myMethod(self):
        obj = creator_obj('a')
        return obj(2, 3)


def creator_obj(value):
    if value == 'a':
        return hello
    if value == 'b':
        return hello1


def hello(a, b):
    z = a+b
    return z


def hello1(a, b):
    z = a+b
    return z


def Method1():
    return Method1


obj = Method1()
print(obj)

b = B().myMethod()
print(b)





