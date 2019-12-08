from django.http import JsonResponse

# Create your views here.
from rest_framework import generics
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST

from A.settings import DISTANCE_KILOMETRE_LIMIT, GOOGLE_API_KEY
from Reservation.models import Ride, Stop, Route
from User.decorators import login_decorator


from math import cos, asin, sqrt
import requests


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

    @staticmethod
    def catch_distance_time(start_lat, start_lon, stop_lat, stop_lon):

        distance_matrix_api_url = 'https://maps.googleapis.com/maps/api/distancematrix/json?'

        map_data = requests.get(distance_matrix_api_url + 'origins={},{}'.format(start_lat, start_lon) +
                                '&destinations={},{}'.format(stop_lat, stop_lon) +
                                '&key={}'.format(GOOGLE_API_KEY))

        a = map_data.json()
        elements = a['rows'][0].get('elements')
        _list_distance = elements[0].get('distance')
        _list_duration = elements[0].get('duration')

        distance = _list_distance['text']
        duration = _list_duration['text']

        float_distance = distance.split(' ')

        duration_and_distance = {'distance': float(float_distance[0]), 'duration': duration}

        return duration_and_distance

    @login_decorator
    def post(self, request, data=None):
        try:
            start_lat = request.data.get('start_lat')
            start_lon = request.data.get('start_lon')
            stop_lat = request.data.get('stop_lat')
            stop_lon = request.data.get('stop_lon')

            available_rides = []

            start_lat_lon_ = {'lat': float(start_lat), 'lon': float(start_lon)}
            stop_lat_lon_ = {'lat': float(stop_lat), 'lon': float(stop_lon)}

            ride_obj = Ride.objects.filter(is_complete=False)
            if not ride_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No Ride Available.',
                })

            for rides in ride_obj:
                ride = BusRoute.return_stops_of_a_ride(ride_obj=rides,
                                                       start_latitude=start_lat_lon_['lat'],
                                                       start_longitude=start_lat_lon_['lon'],
                                                       stop_latitude=stop_lat_lon_['lat'],
                                                       stop_longitude=stop_lat_lon_['lon'],)

                pick_ul = ride.get('pick-up-location')
                drop_ul = ride.get('drop-off-location')
                if pick_ul and drop_ul:
                    available_rides.append(ride)

            return JsonResponse({
                'status': HTTP_200_OK,
                'rides': available_rides,
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
            ride = {}

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

                start_d = BusRoute.catch_distance_time(stops_obj[i].latitude, stops_obj[i].longitude,
                                                       start_latitude, start_longitude)
                nearest_user_stops[i].update({
                    'start_distance': start_d['distance'],
                    'start_duration': start_d['duration'],
                })

                stop_d = BusRoute.catch_distance_time(stops_obj[i].latitude, stops_obj[i].longitude,
                                                      stop_latitude, stop_longitude)
                nearest_user_stops[i].update({
                    'stop_distance': stop_d['distance'],
                    'stop_duration': stop_d['duration'],
                })

            for stops in range(len(nearest_user_stops)):
                if nearest_user_stops[stops]['start_distance'] < DISTANCE_KILOMETRE_LIMIT:

                    stop = ride.get('pick-up-location')
                    if stop:
                        stop.append({
                            'name': nearest_user_stops[stops]['stop_name'],
                            'time': nearest_user_stops[stops]['start_duration'],
                        })
                    else:
                        ride.update({
                            'vehicle_no_plate': ride_obj.vehicle_id.vehicle_no_plate,
                            'seats_left': ride_obj.seats_left,
                            'pick-up-location': [{
                                'name': nearest_user_stops[stops]['stop_name'],
                                'time': nearest_user_stops[stops]['start_duration'],
                            }]
                        })

                if nearest_user_stops[stops]['stop_distance'] < DISTANCE_KILOMETRE_LIMIT:

                    stop = ride.get('drop-off-location')
                    if stop:
                        stop.append({
                                'name': nearest_user_stops[stops]['stop_name'],
                                'time': nearest_user_stops[stops]['stop_duration'],
                            })
                    else:
                        ride.update({
                            'vehicle_no_plate': ride_obj.vehicle_id.vehicle_no_plate,
                            'seats_left': ride_obj.seats_left,
                            'drop-off-location': [{
                                'name': nearest_user_stops[stops]['stop_name'],
                                'time': nearest_user_stops[stops]['stop_duration'],
                            }],
                        })

            return ride

        except Exception as e:
            print(str(e))
            return False

