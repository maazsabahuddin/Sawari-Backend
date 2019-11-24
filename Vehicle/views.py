from django.http import JsonResponse
from rest_framework import generics
from rest_framework.generics import GenericAPIView
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_200_OK

from User.decorators import login_decorator


class Vehicle(GenericAPIView):

    @login_decorator
    def add_vehicle(self, request):
        user = self.user

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


class VehicleRoute(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data):
        try:
            user = data['user']
            from_location = request.data.get('from')
            to_location = request.data.get('to')

            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No user found',
                })

            if not (from_location or to_location):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': "Source/Destination cannot be empty",
                })

            ride_obj = VehicleRoute.get_vehicle(from_location, to_location)

            if not ride_obj:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No Ride available right now',
                })

            return JsonResponse({
                'status': HTTP_200_OK,
                'buses': list(ride_obj),
            })

            # ride_list = list(ride_obj)
            # return JsonResponse(
            #     ride_list,
            #     safe=False,
            # )

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': "Server Error.",
            })

    @staticmethod
    def get_vehicle(from_location, to_location):
        ride_obj = Ride.objects.filter(vehicle_id__from_loc=from_location, vehicle_id__to_loc=to_location) \
            .values('seats_left', 'vehicle_id__vehicle_no_plate')

        if ride_obj:
            return ride_obj


