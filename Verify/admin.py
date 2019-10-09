from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, Customer, Captain

admin.site.register(User)
admin.site.register(Customer)
admin.site.register(Captain)

