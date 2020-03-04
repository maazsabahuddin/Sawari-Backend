from django.contrib import admin
from Reservation.models import Reservation, Ride, Vehicle, Route, Stop, RouteStops

# Register your models here.
admin.site.register(Reservation)
admin.site.register(Ride)
admin.site.register(Vehicle)
admin.site.register(Route)
admin.site.register(Stop)
admin.site.register(RouteStops)
