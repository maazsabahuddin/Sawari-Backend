from django.http import JsonResponse
from rest_framework import generics
from rest_framework.generics import GenericAPIView
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_200_OK

from Reservation.models import Ride
from User.decorators import login_decorator


class Vehicle(GenericAPIView):

    @login_decorator
    def add_vehicle(self, request, data=None):
        user = data['user']

        if not user:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Invalid token'
            })

        vehicle_no_plate = request.data.get('vehicle_no_plate')
        driver_ids = request.data.get('driver_ids')
        owner = request.data.get('owner')
        brand = request.data.get('brand')
        max_seats = request.data.get('max_seats')
        from_loc = request.data.get('from_loc')
        to_loc = request.data.get('to_loc')

        if not (vehicle_no_plate and driver_ids and owner and max_seats and from_loc and to_loc and brand):
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Missing requirements.'
            })



