from django.http import JsonResponse
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_200_OK

from Reservation.models import Reservation, Route, Ride, Vehicle, Stop
from RideSchedule.exceptions import RideNotAvailable, RideException, NotEnoughSeats, FieldMissing
from User.exceptions import UserNotFound, UserException
from Payment.exceptions import PaymentMethod, Payment
from User.models import Customer


def reserve_ride_decorator(f):

    def decorated_function(*args):
        try:
            request = args[1]
            user = args[2]['user']
            vehicle_no_plate = request.data.get('vehicle_no_plate')
            req_seats = request.data.get('req_seats')
            pick_up_point_stop_id = request.data.get('pick_up_point_stop_id')
            drop_up_point_stop_id = request.data.get('drop_up_point_stop_id')
            payment_method = request.data.get('payment_method')
            arrival_time = request.data.get('arrival_time')
            departure_time = request.data.get('departure_time')
            ride_date = request.data.get('ride_date')
            route_id = request.data.get('route_id')

            if not (vehicle_no_plate or req_seats or pick_up_point_stop_id or drop_up_point_stop_id or arrival_time
                    or ride_date):
                raise RideException(status_code=405)

            if payment_method == "Foree":
                raise Payment(status_code=501)

            customer = Customer.objects.filter(user=user).first()
            if not customer:
                raise UserException(status_code=404)

            vehicle_obj = Vehicle.objects.filter(vehicle_no_plate=vehicle_no_plate).first()
            route_obj = Route.objects.filter(route_id=route_id).first()
            ride_obj = Ride.objects.filter(vehicle_id=vehicle_obj.id, is_complete=False,
                                           route_id=route_obj.id).first()

            if not ride_obj:
                raise RideException(status_code=404)

            if ride_obj.seats_left < int(req_seats):
                raise RideException(status_code=400)

            route_obj = ride_obj.route_id
            stops_obj = route_obj.stop_ids.get_queryset()

            # Yeh cross check krna hay k yeh stop is ride k stops mae lie krta b hay ya nahi..
            # just bool true or false make a method.

            pick_up_stop_obj = Stop.objects.filter(id=pick_up_point_stop_id).first()
            pick_up_stop_name = pick_up_stop_obj.name
            pick_up_stop_lat_long = (pick_up_stop_obj.latitude, pick_up_stop_obj.longitude)

            drop_off_stop_obj = Stop.objects.filter(id=drop_up_point_stop_id).first()
            drop_off_stop_name = drop_off_stop_obj.name
            drop_off_stop_lat_long = (drop_off_stop_obj.latitude, drop_off_stop_obj.longitude)

            from A.settings.base import gmaps
            result = gmaps.distance_matrix(pick_up_stop_lat_long, drop_off_stop_lat_long, mode='driving')
            kilometer = float(result['rows'][0]['elements'][0]['distance']['text'].split(' ')[0])

            return f(args[0], request, user=user, customer=customer, vehicle_no_plate=vehicle_no_plate,
                     req_seats=req_seats, pick_up_point=pick_up_stop_name, drop_up_point=drop_off_stop_name,
                     kilometer=kilometer, payment_method=payment_method, ride_date=ride_date,
                     arrival_time=arrival_time, departure_time=departure_time)

        except RideException as e:
            if e.status_code == 404:
                raise RideNotAvailable(status_code=405, message="No such ride available right now.")
            if e.status_code == 400:
                raise NotEnoughSeats(status_code=400, message="Not enough seats.")
            if e.status_code == 405:
                raise FieldMissing(status_code=400, message="Field Missing")

        except Payment as e:
            if e.status_code == 501:
                raise PaymentMethod(status_code=501, message="Not Implemented")

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

