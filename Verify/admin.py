from django.contrib import admin
from .models import User, Customer, Captain, Vehicle, Ride, Reservation, \
    PaymentMethod, Pricing, UserRideDetail

admin.site.register(User)
admin.site.register(Customer)
admin.site.register(Captain)
admin.site.register(Vehicle)
admin.site.register(Ride)
admin.site.register(Reservation)
admin.site.register(PaymentMethod)
admin.site.register(Pricing)
admin.site.register(UserRideDetail)

