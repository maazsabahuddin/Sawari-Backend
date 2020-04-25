from django.contrib import admin
from .models import User, Customer, Captain, UserOtp, Place, PlaceDetail

admin.site.register(User)
admin.site.register(Customer)
admin.site.register(Captain)
admin.site.register(UserOtp)
admin.site.register(Place)
admin.site.register(PlaceDetail)
