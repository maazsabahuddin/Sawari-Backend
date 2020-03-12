from django.http import JsonResponse
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_200_OK

import RideSchedule
from Payment.models import PaymentMethod
from Reservation.models import Reservation, Route, Ride, Vehicle, Stop
from RideSchedule.exceptions import RideNotAvailable, RideException, NotEnoughSeats, FieldMissing, StopNotExist
from User.exceptions import UserNotFound, UserException
from Payment.exceptions import PaymentException, PaymentMethodException, Fare
from User.models import Customer


def reserve_ride_decorator(f):

    def decorated_function(*args):
        try:
            request = args[1]
            user = args[2]['user']
            vehicle_no_plate = request.data.get('vehicle_no_plate')
            req_seats = request.data.get('req_seats')
            pick_up_point_stop_id = request.data.get('pick_up_stop_id')
            drop_off_point_stop_id = request.data.get('drop_off_stop_id')
            payment_method = request.data.get('payment_method')
            arrival_time = request.data.get('arrival_time')
            departure_time = request.data.get('departure_time')
            ride_date = request.data.get('ride_date')
            ride_start_time = request.data.get('ride_start_time')
            route_id = request.data.get('route_id')
            fare_per_person = request.data.get('fare_per_person')
            kilometer = request.data.get('kilometer')
            total_fare = request.data.get('total_fare')
            fare_per_km = request.data.get('fare_per_km')

            if not (vehicle_no_plate or req_seats or pick_up_point_stop_id or drop_off_point_stop_id or arrival_time
                    or ride_date or fare_per_person, kilometer or total_fare or fare_per_km):
                raise RideException(status_code=405)

            payment_method_obj = PaymentMethod.objects.filter(payment_method=payment_method).first()
            if not payment_method_obj:
                raise PaymentException(status_code=501)

            if payment_method != "Cash":
                raise PaymentException(status_code=501)

            customer = Customer.objects.filter(user=user).first()
            if not customer:
                raise UserException(status_code=404)

            from datetime import date, time
            # field hard coded sey hatani hay.
            ride_obj = Ride.objects.filter(vehicle_id__vehicle_no_plate='XYZ-756', route_id__route_id='JC-121',
                                           start_time__date=date(2020, 3, 12), start_time__time=time(20, 50, 00),
                                           is_complete=False)
            if not ride_obj:
                raise RideException(status_code=404)

            if ride_obj[0].seats_left < int(req_seats):
                raise RideException(status_code=400)

            if ride_obj[0].seats_left == 0:
                raise RideException(status_code=416)

            route_obj = ride_obj[0].route_id

            from RideSchedule.tests import ride_stops_check
            result = ride_stops_check(ride_stops=route_obj.stop_ids.get_queryset(),
                                      pick_up_stop_id=int(pick_up_point_stop_id),
                                      drop_off_stop_id=int(drop_off_point_stop_id))

            if not result:
                raise RideException(status_code=410)

            from RideSchedule.views import BookRide
            fare_per_km_db = BookRide.price_per_km()
            if float(fare_per_km) != fare_per_km_db:
                raise PaymentException(status_code=502)

            pick_up_stop_obj = Stop.objects.filter(id=pick_up_point_stop_id).first()
            drop_off_stop_obj = Stop.objects.filter(id=drop_off_point_stop_id).first()

            if not (pick_up_stop_obj or drop_off_stop_obj):
                raise RideException(status_code=410)

            pick_up_stop_name = pick_up_stop_obj.name
            pick_up_stop_lat_long = (pick_up_stop_obj.latitude, pick_up_stop_obj.longitude)

            drop_off_stop_name = drop_off_stop_obj.name
            drop_off_stop_lat_long = (drop_off_stop_obj.latitude, drop_off_stop_obj.longitude)

            # from A.settings.base import gmaps
            # result = gmaps.distance_matrix(pick_up_stop_lat_long, drop_off_stop_lat_long, mode='driving')
            # kilometer = float(result['rows'][0]['elements'][0]['distance']['text'].split(' ')[0])

            return f(args[0], request, user=user, customer=customer, vehicle_no_plate=vehicle_no_plate,
                     req_seats=req_seats, pick_up_stop_name=pick_up_stop_name, drop_off_stop_name=drop_off_stop_name,
                     kilometer=kilometer, ride_obj=ride_obj[0], arrival_time=arrival_time,
                     departure_time=departure_time, fare_per_person=float(fare_per_person), total_fare=float(total_fare),
                     fare_per_km=float(fare_per_km), payment_method_obj=payment_method_obj)

        except RideException as e:
            if e.status_code == 404:
                raise RideNotAvailable(status_code=405, message="No such ride available right now.")
            if e.status_code == 400:
                raise NotEnoughSeats(status_code=400, message="Not enough seats.")
            if e.status_code == 405:
                raise NotEnoughSeats(status_code=416, message="Fully booked.")
            if e.status_code == 405:
                raise FieldMissing(status_code=400, message="Field Missing.")
            if e.status_code == 410:
                raise StopNotExist(status_code=400, message="No stops exist.",
                                   dev_message="such stops not exist in ride.")

        except PaymentException as e:
            if e.status_code == 501:
                raise PaymentMethodException(status_code=501, message="Not Implemented")
            if e.status_code == 502:
                raise Fare(status_code=502, message="Fare Exception")

        except UserException as e:
            if e.status_code == 404:
                raise UserNotFound(status_code=404, message="User not found")

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'Server Error. ' + str(e),
            })

    return decorated_function


def confirm_ride(f):

    def confirm_ride_decorator(*args):
        try:
            request = args[1]
            user = args[2]['user']
            reservation_number = request.data.get('reservation_number')

            reservation_number_obj = Reservation.objects.filter(reservation_number=reservation_number).first()
            if not reservation_number_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid reservation number.',
                })

            if reservation_number_obj.is_confirmed:
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'Ride is confirmed.',
                })

            print(reservation_number_obj.customer_id)
            customer = Customer.objects.filter(id=reservation_number_obj.customer_id.id).first()

            if not user == customer.user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'False user.',
                })

            customer_obj = Customer.objects.filter(user=user).first()
            if not customer_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'is_customer field is false.'
                })

            return f(args[0], request, user=user, customer_obj=customer, reservation_number=reservation_number_obj)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })

    return confirm_ride_decorator


def cancel_ride(f):

    def cancel_ride_decorator(*args):
        try:
            request = args[1]
            user = args[2]['user']
            reservation_number = request.data.get('reservation_number')

            reservation_number_obj = Reservation.objects.filter(reservation_number=reservation_number).first()
            if not reservation_number_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid reservation number.',
                })

            if not reservation_number_obj.is_confirmed:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Ride already cancelled.',
                })

            customer = Customer.objects.filter(id=reservation_number_obj.customer_id.id).first()

            if not user == customer.user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'False user.',
                })

            customer_obj = Customer.objects.filter(user=user).first()
            if not customer_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'is_customer field is false.'
                })

            return f(args[0], request, user=user, customer_obj=customer, reservation_number=reservation_number_obj)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })

    return cancel_ride_decorator

