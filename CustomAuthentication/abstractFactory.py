# from abc import abstractmethod
#
# from django.contrib.auth.hashers import make_password
#
# from User.models import User
#
#
# class AbstractProductUser:
#
#     @abstractmethod
#     def user_function(self):
#         pass
#
#
# class A(AbstractProductUser):
#
#     def user_function(self):
#         return "Hello World"
#         # user = User.objects.create(
#         #     email=email,
#         #     password=make_password(password),
#         #     phone_number=None,
#         #     is_active=False,
#         # )
#         # return user
#
#
# class UserFactory:
#
#     @abstractmethod
#     def add_user(self):
#         pass
#
#
# class AddUserFactory(UserFactory):
#
#     def add_user(self):
#         return A()
#
#
# if __name__ == "__main__":
#
#     obj = AddUserFactory().add_user()
