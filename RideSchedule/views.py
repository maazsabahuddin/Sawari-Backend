import datetime

import pytz
from django.http import JsonResponse
from django.utils import timezone

# Create your views here.
from rest_framework import generics
from rest_framework.status import HTTP_404_NOT_FOUND, HTTP_200_OK, HTTP_400_BAD_REQUEST

from A.settings.base import DISTANCE_KILOMETRE_LIMIT, gmaps, local_tz, STOP_WAIT_TIME, SHOW_RIDES_TODAY_ONLY, \
    SHOW_RIDE_DAYS

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

    @staticmethod
    def ride_time(ride_obj, lat1, lon1):
        try:
            route_obj = Route.objects.filter(ride_id=ride_obj.id).first()
            ride_vehicle = Stop.objects.filter(route_ids=route_obj.id).first()

            ride_latitude = ride_vehicle.latitude
            ride_longitude = ride_vehicle.longitude

            origin = (ride_latitude, ride_longitude)
            destination = (lat1, lon1)

            duration = gmaps.distance_matrix(origin, destination, mode='driving')["rows"][0]["elements"][0][
                "duration"]["text"]
            duration = duration.split(' ')[0]
            return duration

        except TypeError:
            return False

    @staticmethod
    def distance_and_duration(**kwargs):
        try:
            pick_up_lat_lon = kwargs.get('pick_up_lat_lon')
            drop_off_lat_lon = kwargs.get('drop_off_lat_lon')
            stops_obj = kwargs.get('stops_obj')
            stops = kwargs.get('stops')

            pick_up_result = gmaps.distance_matrix(stops, pick_up_lat_lon, mode='walking')
            drop_off_result = gmaps.distance_matrix(stops, drop_off_lat_lon, mode='walking')

            stop_details = []

            if len(pick_up_result) == len(drop_off_result):
                for i in range(len(pick_up_result['rows'])):
                    stop_details.append({
                        'stop_id': stops_obj[i].id,
                        'stop_name': stops_obj[i].name,
                        'lat_long': stops[i],
                        'pick-up-location-distance':
                            float(pick_up_result['rows'][i]['elements'][0]['distance']['text'].split(' ')[0]),
                        'pick-up-location-duration': pick_up_result['rows'][i]['elements'][0]['duration']['text'],

                        'drop-off-location-distance':
                            float(drop_off_result['rows'][i]['elements'][0]['distance']['text'].split(' ')[0]),
                        'drop-off-location-duration': drop_off_result['rows'][i]['elements'][0]['duration']['text'],
                    })

            return stop_details

        except TypeError:
            return False

    @staticmethod
    def stop_to_stop_distance(**kwargs):
        try:
            stops_obj = kwargs.get('stops_obj')
            stops = kwargs.get('stops')

            stops = []
            for stop in stops_obj:
                stops.append(
                    (stop.latitude, stop.longitude)
                )

            # calculating duration from stop 1 to each stop.
            first_stop = stops[0]
            result = gmaps.distance_matrix(first_stop, stops, mode='driving')

            stop_details = []

            if len(stops) == len(result['rows'][0]['elements']):
                for i in range(1, len(result['rows'][0]['elements']) + 1):
                    stop_details.append({
                        'stop_name': stops_obj[i-1].name,
                        'distance': float(result['rows'][0]['elements'][i-1]['distance']['text'].split(' ')[0]),
                        'duration': int(result['rows'][0]['elements'][i-1]['duration']['text'].split(' ')[0])
                                    + (STOP_WAIT_TIME * i),
                    })

            return stop_details

        except TypeError:
            return False

    @staticmethod
    def utc_to_local(utc_dt):
        local_dt = utc_dt.replace(tzinfo=pytz.utc).astimezone(local_tz)
        return local_tz.normalize(local_dt)

    @staticmethod
    def ride_arrival_time(**kwargs):

        ride_obj = kwargs.get('ride_obj')
        stop_name = kwargs.get('stop_name')
        stop_duration = kwargs.get('stops_duration')
        duration = 0

        for i in range(len(stop_duration)):
            if stop_duration[i]['stop_name'] == stop_name:
                duration = stop_duration[i]['duration']
                break

        ride_start_time = ride_obj.start_time
        ride_start_time_local = BusRoute.utc_to_local(ride_start_time)

        ride_arrival_time = (ride_start_time_local + datetime.timedelta(0, duration*60)).time()
        return ride_arrival_time

    @staticmethod
    def append_available_rides(**kwargs):
        try:
            start_latitude = kwargs.get('start_latitude')
            start_longitude = kwargs.get('start_longitude')
            stop_latitude = kwargs.get('stop_latitude')
            stop_longitude = kwargs.get('stop_longitude')
            ride_obj = kwargs.get('ride_obj')
            ride_date = kwargs.get('ride_date')
            route_of_ride = kwargs.get('route_of_ride')

            ride = BusRoute.return_stops_of_a_ride(ride_obj=ride_obj,
                                                   ride_date=ride_date,
                                                   start_latitude=start_latitude,
                                                   start_longitude=start_longitude,
                                                   stop_latitude=stop_latitude,
                                                   stop_longitude=stop_longitude, )

            pick_ul = ride.get('pick-up-location')
            shortest_pick_ul = sorted(pick_ul, key=lambda k: k["distance"])[0]
            drop_ul = ride.get('drop-off-location')
            shortest_dropoff_ul = sorted(drop_ul, key=lambda k: k["distance"])[0]

            if pick_ul and drop_ul:
                ride.pop('pick-up-location', None)
                ride.pop('drop-off-location', None)

                route_id = {'route_id': route_of_ride}
                ride_pick_up_location = {'pick-up-location': shortest_pick_ul}
                ride_dropoff_location = {'drop-off-location': shortest_dropoff_ul}
                ride_date_append = {'ride_date': ride_date}

                ride.update(route_id)
                ride.update(ride_date_append)
                ride.update(ride_pick_up_location)
                ride.update(ride_dropoff_location)
                return ride

        except:
            pass

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

            datetime_now = BusRoute.utc_to_local(timezone.now())
            for rides in ride_obj:
                ride_datetime = BusRoute.utc_to_local(rides.start_time)
                route_obj = Route.objects.filter(ride_id=rides.id).first()
                route_of_ride = route_obj.route_id

                if SHOW_RIDES_TODAY_ONLY:
                    if ride_datetime.date() == datetime_now.date() and datetime_now < ride_datetime:
                        available_rides.append(
                            BusRoute.append_available_rides(ride_obj=rides,
                                                            ride_date=ride_datetime.date(),
                                                            start_latitude=start_lat_lon_['lat'],
                                                            start_longitude=start_lat_lon_['lon'],
                                                            stop_latitude=stop_lat_lon_['lat'],
                                                            stop_longitude=stop_lat_lon_['lon'],
                                                            route_of_ride=route_of_ride,))

                else:
                    no_of_days = SHOW_RIDE_DAYS
                    extended_datetime = datetime_now + datetime.timedelta(days=no_of_days-1)

                    if extended_datetime == datetime_now:
                        available_rides.append(
                            BusRoute.append_available_rides(ride_obj=rides,
                                                            ride_date=ride_datetime.date(),
                                                            start_latitude=start_lat_lon_['lat'],
                                                            start_longitude=start_lat_lon_['lon'],
                                                            stop_latitude=stop_lat_lon_['lat'],
                                                            stop_longitude=stop_lat_lon_['lon'],
                                                            route_of_ride=route_of_ride, ))

                    if extended_datetime > ride_datetime > datetime_now:
                        available_rides.append(
                            BusRoute.append_available_rides(ride_obj=rides,
                                                            ride_date=ride_datetime.date(),
                                                            start_latitude=start_lat_lon_['lat'],
                                                            start_longitude=start_lat_lon_['lon'],
                                                            stop_latitude=stop_lat_lon_['lat'],
                                                            stop_longitude=stop_lat_lon_['lon'],
                                                            route_of_ride=route_of_ride, ))

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
            ride_date = kwargs.get('ride_date')

            ride = {}

            if not ride_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No Ride Available.',
                })

            route_obj = Route.objects.filter(ride_id=ride_obj.id).first()
            # stops_obj = Stop.objects.filter(route_ids=route_obj.id)

            stops_lat_lng = []
            stops_obj = route_obj.stop_ids.get_queryset()
            for stop in stops_obj:
                stops_lat_lng.append(
                    (stop.latitude, stop.longitude)
                )

            nearest_user_stops = BusRoute.distance_and_duration(stops_obj=stops_obj,
                                                                stops=stops_lat_lng,
                                                                pick_up_lat_lon=(start_latitude, start_longitude),
                                                                drop_off_lat_lon=(stop_latitude, stop_longitude),)

            stops_duration = BusRoute.stop_to_stop_distance(stops_obj=route_obj.stop_ids.get_queryset(),)

            for stops in range(len(nearest_user_stops)):
                if nearest_user_stops[stops]['pick-up-location-distance'] < DISTANCE_KILOMETRE_LIMIT:

                    stop = ride.get('pick-up-location')
                    if stop:
                        stop.append({
                            'stop_id': nearest_user_stops[stops]['stop_id'],
                            'stop_name': nearest_user_stops[stops]['stop_name'],
                            'duration': nearest_user_stops[stops]['pick-up-location-duration'],
                            'distance': str(nearest_user_stops[stops]['pick-up-location-distance']) + " Km",
                            'arrival_time': BusRoute.ride_arrival_time(
                                ride_obj=ride_obj,
                                stop_name=nearest_user_stops[stops]['stop_name'],
                                stops_duration=stops_duration, ),
                            # 'date': ride_date,
                        })
                    else:
                        ride.update({
                            'vehicle_no_plate': ride_obj.vehicle_id.vehicle_no_plate,
                            'seats_left': ride_obj.seats_left,
                            'pick-up-location': [{
                                'stop_id': nearest_user_stops[stops]['stop_id'],
                                'stop_name': nearest_user_stops[stops]['stop_name'],
                                'duration': nearest_user_stops[stops]['pick-up-location-duration'],
                                'distance': str(nearest_user_stops[stops]['pick-up-location-distance']) + " Km",
                                'arrival_time': BusRoute.ride_arrival_time(
                                    ride_obj=ride_obj,
                                    stop_name=nearest_user_stops[stops]['stop_name'],
                                    stops_duration=stops_duration,),
                                # 'date': ride_date,
                            }]
                        })

                if nearest_user_stops[stops]['drop-off-location-distance'] < DISTANCE_KILOMETRE_LIMIT:

                    stop = ride.get('drop-off-location')
                    if stop:
                        stop.append({
                                'stop_id': nearest_user_stops[stops]['stop_id'],
                                'stop_name': nearest_user_stops[stops]['stop_name'],
                                'duration': nearest_user_stops[stops]['drop-off-location-duration'],
                                'distance': str(nearest_user_stops[stops]['drop-off-location-distance']) + " Km",
                                'departure_time': BusRoute.ride_arrival_time(
                                    ride_obj=ride_obj,
                                    stop_name=nearest_user_stops[stops]['stop_name'],
                                    stops_duration=stops_duration, ),
                                # 'date': ride_date,
                            })
                    else:
                        ride.update({
                            'vehicle_no_plate': ride_obj.vehicle_id.vehicle_no_plate,
                            'seats_left': ride_obj.seats_left,
                            'drop-off-location': [{
                                'stop_id': nearest_user_stops[stops]['stop_id'],
                                'stop_name': nearest_user_stops[stops]['stop_name'],
                                'duration': nearest_user_stops[stops]['drop-off-location-duration'],
                                'distance': str(nearest_user_stops[stops]['drop-off-location-distance']) + " Km",
                                'departure_time': BusRoute.ride_arrival_time(
                                    ride_obj=ride_obj,
                                    stop_name=nearest_user_stops[stops]['stop_name'],
                                    stops_duration=stops_duration, ),
                                # 'date': ride_date,
                            }],
                        })

            return ride

        except Exception as e:
            print(str(e))
            return False

