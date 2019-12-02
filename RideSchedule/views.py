from django.http import JsonResponse
from django.shortcuts import render


# Create your views here.
from rest_framework import generics
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST

from Reservation.models import Ride
from User.decorators import login_decorator


from math import cos, asin, sqrt


def distance(lat1, lon1, lat2, lon2):
    p = 0.017453292519943295
    a = 0.5 - cos((lat2-lat1)*p)/2 + cos(lat1*p)*cos(lat2*p) * (1-cos((lon2-lon1)*p)) / 2
    return 12742 * asin(sqrt(a))


def closest(data, v):
    return min(data, key=lambda p: distance(v['lat'], v['lon'], p['lat'], p['lon']))


tempDataList = [{'lat': 39.7612992, 'lon': -86.1519681},
                {'lat': 39.762241,  'lon': -86.158436 },
                {'lat': 39.7622292, 'lon': -86.1578917}, ]


v = {'lat': 39.7622290, 'lon': -86.1519750}
# print(closest(tempDataList, v))


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


class Route(generics.GenericAPIView):

    @login_decorator
    def post(self, request, **kwargs):
        try:
            start_lat = request.data.get('start_lat')
            start_lon = request.data.get('start_lon')
            stop_lat = request.data.get('stop_lat')
            stop_lon = request.data.get('stop_lon')

            start_lat_lon_ = {'lat': float(start_lat), 'lon': float(start_lon)}
            start_lat_lon_ = {'lat': float(stop_lat), 'lon': float(stop_lon)}




        except Exception as e:
            return JsonResponse({
                'status': HTTP_200_OK,
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
