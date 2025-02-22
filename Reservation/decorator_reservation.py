from django.http import JsonResponse
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND

from Reservation.models import Reservation, Route, Ride, Vehicle
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
            # kilometer = request.data.get('kilometer')
            payment_method = request.data.get('payment_method')
            arrival_time = request.data.get('arrival_time')
            ride_date = request.data.get('ride_date')

            if not (vehicle_no_plate or req_seats or pick_up_point_stop_id or drop_up_point_stop_id or arrival_time):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Field Missing.',
                })

            if payment_method == "Card":
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'Card transaction coming soon.',
                })

            if not ride_date:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'ride_date needed.',
                })

            customer = Customer.objects.filter(user=user).first()
            if not customer:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'is_customer field is false.'
                })

            vehicle_obj = Vehicle.objects.filter(vehicle_no_plate=vehicle_no_plate).first()
            ride_obj = Ride.objects.filter(vehicle_id=vehicle_obj.id, is_complete=False).first()

            if not ride_obj:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No ride available right now.',
                })

            if ride_obj.seats_left < int(req_seats):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': req_seats + " seats are not available.",
                })

            route_obj = Route.objects.filter(ride_id=ride_obj.id).first()
            stops_obj = route_obj.stop_ids.get_queryset()

            pick_up_point = ''
            drop_off_point = ''
            pick_up_stop = ''
            drop_off_stop = ''

            for stop in stops_obj:
                if stop.id == int(pick_up_point_stop_id):
                    pick_up_point = stop.name
                    pick_up_stop = (stop.latitude, stop.longitude)

                elif stop.id == int(drop_up_point_stop_id):
                    drop_off_point = stop.name
                    drop_off_stop = (stop.latitude, stop.longitude)

            from A import gmaps
            result = gmaps.distance_matrix(pick_up_stop, drop_off_stop, mode='driving')
            kilometer = float(result['rows'][0]['elements'][0]['distance']['text'].split(' ')[0])

            if not (pick_up_point or drop_off_point):
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No such stops exist in this ride.',
                })

            return f(args[0], request, user=user, customer=customer, vehicle_no_plate=vehicle_no_plate,
                     req_seats=req_seats, pick_up_point=pick_up_point, drop_up_point=drop_off_point,
                     kilometer=kilometer, payment_method=payment_method, ride_date=ride_date, arrival_time=arrival_time)

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
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Ride already reserved.',
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

