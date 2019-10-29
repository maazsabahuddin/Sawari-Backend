from django.shortcuts import render


# Create your views here.
from Payment.models import Pricing
from Reservation.models import Ride


class RideMixin(object):

    @staticmethod
    def kilometer_price():
        price_obj = Pricing.objects.filter().first()
        if price_obj:
            return price_obj.price_per_km

    @staticmethod
    def fare_price(price_per_km, kilometer):
        if price_per_km:
            amount = price_per_km * kilometer
            return round(amount)

    @staticmethod
    def get_ride_obj(vehicle_no_plate):
        vehicle_obj = Ride.objects.filter(vehicle_id__vehicle_no_plate=vehicle_no_plate).first()
        if vehicle_obj:
            return vehicle_obj

    @staticmethod
    def update_ride(vehicle_no_plate, seats_booked: int):
        ride_obj = Ride.objects.filter(vehicle_id__vehicle_no_plate=vehicle_no_plate).first()
        if ride_obj:
            seats_left = ride_obj.seats_left - int(seats_booked)
            ride_obj.seats_left = seats_left
            ride_obj.save()
            return True
        return False

