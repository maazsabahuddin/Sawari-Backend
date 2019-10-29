from django.contrib import admin
from .models import User, Customer, Captain, UserOtp

admin.site.register(User)
admin.site.register(Customer)
admin.site.register(Captain)
admin.site.register(UserOtp)

