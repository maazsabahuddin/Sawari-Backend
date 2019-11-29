import datetime

from django.db import models
from User.models import Captain, Customer


class Vehicle(models.Model):
    vehicle_no_plate = models.CharField(blank=False, null=False, max_length=10, unique=True)
    driver_ids = models.ManyToManyField(Captain, related_name='drivers', blank=True)
    owner = models.ForeignKey(Captain, on_delete=models.CASCADE)
    brand = models.CharField(blank=True, max_length=20)
    max_seats = models.IntegerField(blank=False)
    from_loc = models.CharField(max_length=255)
    to_loc = models.CharField(max_length=255)

    def __str__(self):
        return "Vehicle {} - {}".format(self.id, self.vehicle_no_plate)


class Ride(models.Model):
    driver_ids = models.ManyToManyField(Captain)
    vehicle_id = models.ForeignKey(to='Vehicle', on_delete=models.CASCADE, related_name='driver_vehicle')
    start_time = models.DateTimeField(blank=True, null=True)
    end_time = models.DateTimeField(blank=True, null=True)
    route = models.CharField(blank=False, max_length=256)
    seats_left = models.IntegerField(blank=False, null=False)

    def __str__(self):
        return "Ride {} - {}".format(self.id, self.vehicle_id.vehicle_no_plate)


class Reservation(models.Model):
    reservation_number = models.CharField(max_length=20, unique=True)
    customer_id = models.ForeignKey(Customer, on_delete=models.CASCADE)
    ride_id = models.ForeignKey(Ride, on_delete=models.CASCADE)
    reservation_seats = models.IntegerField(blank=False)
    is_confirmed = models.BooleanField(default=False)
    created_date = models.DateField(default=datetime.datetime.today)
    updated_timestamp = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return "{} - {} - {}".format(self.id, self.customer_id.user.email, self.customer_id.user.phone_number)

