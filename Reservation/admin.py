from django.contrib import admin
from Reservation.models import Reservation, Ride, Vehicle, Route, Stop

# Register your models here.
admin.site.register(Reservation)
admin.site.register(Ride)
admin.site.register(Vehicle)
admin.site.register(Route)
admin.site.register(Stop)
