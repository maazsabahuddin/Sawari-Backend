from django.shortcuts import render


# Create your views here.
from Payment.models import Pricing
from Reservation.models import Ride


class RideMixin(object):

    def kilometer_price(self):
        price_obj = Pricing.objects.filter().first()
        if price_obj:
            return price_obj.price_per_km

    def fare_price(self, price_per_km, kilometer):
        if price_per_km:
            amount = price_per_km * kilometer
            return round(amount)

    def get_ride_obj(self, vehicle_no_plate):
        vehicle_obj = Ride.objects.filter(vehicle_id__vehicle_no_plate=vehicle_no_plate).first()
        if vehicle_obj:
            return vehicle_obj
