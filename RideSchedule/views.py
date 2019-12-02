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

            stop_ = []
            ride = []

            start_lat_lon_ = {'lat': float(start_lat), 'lon': float(start_lon)}
            stop_lat_lon_ = {'lat': float(stop_lat), 'lon': float(stop_lon)}

            ride_obj = Ride.objects.filter(is_complete=False)

            for ride_obj in ride_obj:
                route_obj = Route.objects.filter(ride_id=ride_obj.id)

                for route_obj in route_obj:
                    stops_obj = Stop.objects.filter(route_ids=route_obj.id)

                    for i in range(len(stops_obj)):
                        stop_.append({
                            'lat': stops_obj[i].latitude,
                            'lon': stops_obj[i].longitude,
                            'stop_name': stops_obj[i].name,
                        })

                        start_distance = distance_formula(stops_obj[i].latitude, stops_obj[i].longitude,
                                                          start_lat_lon_['lat'], start_lat_lon_['lon'])
                        stop_[i].update({'start_distance': start_distance})

                        stop_distance = distance_formula(stops_obj[i].latitude, stops_obj[i].longitude,
                                                         stop_lat_lon_['lat'], stop_lat_lon_['lon'])
                        stop_[i].update({'stop_distance': stop_distance})

                    for i in range(len(stop_)):
                        if stop_[i]['start_distance'] < DISTANCE_KILOMETRE_LIMIT and \
                                stop_[i]['stop_distance'] < DISTANCE_KILOMETRE_LIMIT:

                            ride.append(ride_obj)
                            break
            print(ride)

            return JsonResponse({
                'status': HTTP_200_OK,
                'message': 'Ok',
                'vehicle_no_plate': ride[0].vehicle_id.vehicle_no_plate,
                'seats_left': ride[0].seats_left,
                'pick_up_point': '',
                'drop_up_point': '',
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })

    # @login_decorator
    # def post(self, request, data=None):
    #
    #     try:
    #         lat = request.data.get('lat')
    #         lon = request.data.get('lon')
    #         lat_float = float(lat)
    #         lon_float = float(lon)
    #         lat_lon_dict = {'lat': lat_float, 'lon': lon_float}
    #
    #         lat_long_bus = []
    #         k = []
    #         final_list_dict = []
    #
    #         bus_route_obj = Ride.objects.filter()
    #
    #         for i in range(len(bus_route_obj)):
    #             lat_long_bus.append(bus_route_obj[i].route)
    #
    #         print(lat_long_bus)
    #         a = str(lat_long_bus[0]).split(',')
    #         print(a)
    #
    #         for i in range(len(a)):
    #             h = a[i]
    #             j = h.split(':')
    #
    #             for z in range(len(j)):
    #                 k.append(float(j[z]))
    #
    #         print(k)
    #
    #         for i in range(len(k)):
    #             x = {'lat': k[i], 'lon': k[i]+1}
    #             final_list_dict.append(x)
    #             i += 1
    #
    #         print(final_list_dict)
    #
    #         closest_point = closest(final_list_dict, lat_lon_dict)
    #         print(closest_point)
    #
    #         return JsonResponse({
    #             'status': HTTP_200_OK,
    #         })
    #
    #     except Exception as e:
    #         return JsonResponse({
    #             'status': HTTP_400_BAD_REQUEST,
    #             'message': str(e),
    #         })




