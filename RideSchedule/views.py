from django.http import JsonResponse
from django.shortcuts import render


# Create your views here.
from rest_framework import generics
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST

from A.settings import DISTANCE_KILOMETRE_LIMIT
from Reservation.models import Ride, Stop, Route
from User.decorators import login_decorator


from math import cos, asin, sqrt


# It returns the result in Kilometer.
# Distance between two points.
def distance_formula(lat1, lon1, lat2, lon2):
    p = 0.017453292519943295
    a = 0.5 - cos((lat2-lat1)*p)/2 + cos(lat1*p)*cos(lat2*p) * (1-cos((lon2-lon1)*p)) / 2
    return 12742 * asin(sqrt(a))


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

        except Exception as e:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': "Server Error." + str(e),
            })

    @staticmethod
    def get_vehicle(from_location, to_location):
        try:
            ride_obj = Ride.objects.filter(vehicle_id__from_loc__contains=from_location,
                                           vehicle_id__to_loc__contains=to_location) \
                .values('seats_left', 'vehicle_id__vehicle_no_plate')

            if ride_obj:
                return ride_obj
        except TypeError:
            return False


class BusRoute(generics.GenericAPIView):

    @login_decorator
    def post(self, request, data=None):
        try:
            start_lat = request.data.get('start_lat')
            start_lon = request.data.get('start_lon')
            stop_lat = request.data.get('stop_lat')
            stop_lon = request.data.get('stop_lon')

            # stop_ = []
            ride = {}

            start_lat_lon_ = {'lat': float(start_lat), 'lon': float(start_lon)}
            stop_lat_lon_ = {'lat': float(stop_lat), 'lon': float(stop_lon)}

            ride_obj = Ride.objects.filter(is_complete=False)
            if not ride_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No Ride Available.',
                })

            for rides in ride_obj:
                ride.update(BusRoute.return_stops_of_a_ride(ride_obj=rides,
                                                            start_latitude=start_lat_lon_['lat'],
                                                            start_longitude=start_lat_lon_['lon'],
                                                            stop_latitude=stop_lat_lon_['lat'],
                                                            stop_longitude=stop_lat_lon_['lon'],))

            print(ride)
            for key in ride.keys():
                print(key.vehicle_id.vehicle_no_plate)
                print(key.seats_left)

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'Ok',
                # 'vehicle_no_plate': ride[Key].vehicle_id.vehicle_no_plate,
                # 'seats_left': ride[0].seats_left,
                # 'pick_up_point': '',
                # 'drop_up_point': '',
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })

    @staticmethod
    def return_stops_of_a_ride(**kwargs):
        try:
            start_latitude = kwargs.get('start_latitude')
            start_longitude = kwargs.get('start_longitude')
            stop_latitude = kwargs.get('stop_latitude')
            stop_longitude = kwargs.get('stop_longitude')

            ride_obj = kwargs.get('ride_obj')
            nearest_user_stops = []
            ride_stops = {}

            if not ride_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No Ride Available.',
                })

            route_obj = Route.objects.filter(ride_id=ride_obj.id).first()
            stops_obj = Stop.objects.filter(route_ids=route_obj.id)

            for i in range(len(stops_obj)):
                nearest_user_stops.append({
                    'lat': stops_obj[i].latitude,
                    'lon': stops_obj[i].longitude,
                    'stop_name': stops_obj[i].name,
                    'start_distance': 0.0,
                    'stop_distance': 0.0,
                })

                start_distance = distance_formula(stops_obj[i].latitude, stops_obj[i].longitude,
                                                  start_latitude, start_longitude)
                nearest_user_stops[i].update({'start_distance': start_distance})

                stop_distance = distance_formula(stops_obj[i].latitude, stops_obj[i].longitude,
                                                 stop_latitude, stop_longitude)
                nearest_user_stops[i].update({'stop_distance': stop_distance})

            print(nearest_user_stops)

            for stops in range(0, len(nearest_user_stops)):
                if nearest_user_stops[stops]['start_distance'] < DISTANCE_KILOMETRE_LIMIT and \
                        nearest_user_stops[stops]['stop_distance'] < DISTANCE_KILOMETRE_LIMIT:

                    if ride_stops.get(ride_obj):
                        ride_stops.get(ride_obj).append(nearest_user_stops[stops]['stop_name'])
                    else:
                        ride_stops.update({ride_obj: [nearest_user_stops[stops]['stop_name']]})

            return ride_stops

        except Exception as e:
            print(str(e))
            return False

