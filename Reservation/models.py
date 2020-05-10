import datetime
from django.utils import timezone
from sortedm2m.fields import SortedManyToManyField
from django.db import models
from User.models import Captain, Customer


class Vehicle(models.Model):
    objects = None
    vehicle_no_plate = models.CharField(blank=False, max_length=10)
    driver_ids = models.ManyToManyField(Captain, related_name='drivers', blank=True)
    owner = models.ForeignKey(Captain, on_delete=models.CASCADE)
    brand = models.CharField(blank=True, max_length=20)
    max_seats = models.IntegerField(blank=False)
    from_loc = models.CharField(max_length=255, blank=True)
    to_loc = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return "Vehicle {} - {}".format(self.id, self.vehicle_no_plate)


class Stop(models.Model):
    objects = None
    name = models.CharField(blank=False, max_length=256)
    latitude = models.FloatField(blank=False, max_length=100)
    longitude = models.FloatField(blank=False, max_length=100)

    # SORT_VALUE_FIELD_NAME = 'sort_value'
    # def __str__(self):
    #     return "{} - {} - Latitude {}, Longitude {}".format(self.id, self.name, self.latitude, self.longitude)

    def __str__(self):
        return "{} - {}".format(self.id, self.name)


class Route(models.Model):
    # A ride is a lap.
    # A ride can have only one route and a route can have multiple rides.

    # SORT_VALUE_FIELD_NAME = 'sort_value'

    objects = None
    route_id = models.CharField(max_length=10, null=True, blank=True)
    # stop_ids = SortedManyToManyField(Stop, sorted=False)
    stop_ids = models.ManyToManyField(Stop, through='RouteStops')
    start_name = models.CharField(blank=False, max_length=50)
    stop_name = models.CharField(blank=False, max_length=50)
    created_date = models.DateTimeField(blank=True, null=True, default=timezone.localtime(timezone.now()))

    def __str__(self):
        return "{} - Route {} = {} - {}".format(self.id, self.route_id, self.start_name, self.stop_name)


class RouteStops(models.Model):
    objects = None
    stop_id = models.ForeignKey(Stop, on_delete=models.CASCADE)
    route_id = models.ForeignKey(Route, on_delete=models.CASCADE)
    sort_value = models.PositiveSmallIntegerField()

    def __str__(self):
        return "Route-id {} - {} - Sort-value {}".format(self.route_id.id, self.stop_id.id, self.sort_value)


class Ride(models.Model):
    objects = None
    driver_ids = models.ManyToManyField(Captain)
    vehicle_id = models.ForeignKey(to='Vehicle', on_delete=models.CASCADE, related_name='driver_vehicle')
    route_id = models.ForeignKey(Route, related_name='ride_route', on_delete=models.CASCADE)
    start_time = models.DateTimeField(blank=True, null=True)
    end_time = models.DateTimeField(blank=True, null=True)
    seats_left = models.IntegerField(blank=False, null=False)
    is_complete = models.BooleanField(default=False)

    def __str__(self):
        return "Ride {} - {} - {} - {}".format(self.id, self.vehicle_id.vehicle_no_plate, self.route_id.route_id,
                                               self.start_time.date())


class Reservation(models.Model):
    objects = None
    reservation_number = models.CharField(max_length=20, unique=True)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)
    ride_id = models.ForeignKey(Ride, on_delete=models.CASCADE)
    reservation_seats = models.IntegerField(blank=False)
    is_confirmed = models.BooleanField(default=False)
    created_date = models.DateField(default=datetime.datetime.today)
    updated_timestamp = models.DateTimeField(blank=True, null=True, default=timezone.localtime(timezone.now()))

    def __str__(self):
        return "{} - {} - {}".format(self.reservation_number, self.customer_id.user.email,
                                     self.customer_id.user.phone_number)


