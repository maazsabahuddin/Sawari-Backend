from tokenize import Token

from django.http import JsonResponse
from rest_framework.status import HTTP_400_BAD_REQUEST

from Payment.models import PaymentMethod
from Reservation.models import Reservation
from User.models import Customer


def reserve_ride_decorator(f):

    def decorated_function(*args):
        try:
            request = args[1]
            user = args[2]['user']
            vehicle_no_plate = request.data.get('vehicle_no_plate')
            req_seats = request.data.get('req_seats')
            pick_up_point = request.data.get('pick_up_point')
            drop_up_point = request.data.get('drop_up_point')
            kilometer = request.data.get('kilometer')
            payment_method = request.data.get('payment_method')

            if not (vehicle_no_plate or req_seats or pick_up_point or drop_up_point or kilometer):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Value Missing.',
                })

            customer = Customer.objects.filter(user=user).first()
            if not customer:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'is_customer field is false.'
                })

            return f(args[0], request, user=user, customer=customer, vehicle_no_plate=vehicle_no_plate,
                     req_seats=req_seats, pick_up_point=pick_up_point, drop_up_point=drop_up_point, kilometer=kilometer,
                     payment_method=payment_method)

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
