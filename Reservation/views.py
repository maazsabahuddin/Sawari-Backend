from datetime import date
from django.db import transaction
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from rest_framework import generics
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_200_OK
from rest_framework.views import APIView

from A.settings import FIXED_FARE, KILOMETER_FARE, SENDER_PHONE_NUMBER
from Payment.models import Pricing, PaymentMethod
# from Payment.views import PaymentMixin
from Reservation.decorator_reservation import reserve_ride_decorator, confirm_ride
from RideSchedule.models import UserRideDetail
from User.context_processors import singleton
from User.decorators import login_decorator
from User.models import Customer
from .models import Reservation, Ride, Vehicle, Route
from .reservation_pattern import ReservationNumber


def fare_object(fixed_fare, kilometer_fare):
    try:
        if kilometer_fare:
            return RideBook.fare_kilometer
        elif fixed_fare:
            return RideBook.fare_fixed

    except TypeError:
        return False


class RideBook(generics.GenericAPIView):

    @staticmethod
    def db_price():
        try:
            price_obj = Pricing.objects.filter().first()
            if price_obj:
                if KILOMETER_FARE:
                    return int(price_obj.price_per_km)
                if FIXED_FARE:
                    return int(price_obj.fixed_fare)

        except TypeError:
            return False

    @staticmethod
    def get_ride_obj(vehicle_no_plate):
        try:
            ride_obj = Ride.objects.filter(vehicle_id__vehicle_no_plate=vehicle_no_plate).first()
            if ride_obj:
                return ride_obj

            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': 'No Ride Available',
            })

        except TypeError:
            return False

    @staticmethod
    def fare_kilometer(**kwargs):
        try:
            total_seats = kwargs.get('req_seats')
            kilometer = kwargs.get('kilometer')

            fare_per_person = RideBook.db_price() * int(kilometer)
            total_fare = fare_per_person * int(total_seats)
            return round(total_fare)

        except TypeError:
            return False

    @staticmethod
    def fare_fixed(**kwargs):
        try:
            total_seats = kwargs.get('req_seats')
            return RideBook.db_price() * int(total_seats)

        except TypeError:
            return False

    @staticmethod
    @transaction.atomic
    def reserve_ride(**kwargs):
        try:
            customer_obj = kwargs.get('customer')
            ride_obj = kwargs.get('ride_obj')
            req_seats = kwargs.get('req_seats')
            pick_up_point = kwargs.get('pick_up_point')
            drop_off_point = kwargs.get('drop_off_point')
            kilometer = kwargs.get('kilometer')
            fare = kwargs.get('fare')
            vehicle_no_plate = kwargs.get('vehicle_no_plate')
            payment_method_obj = kwargs.get('payment_method')
            fare_per_km = RideBook.db_price()

            with transaction.atomic():

                reservation_number = ReservationNumber.generate_new_reservation_number()

                if not reservation_number:
                    return JsonResponse({
                        'status': HTTP_404_NOT_FOUND,
                        'message': "Reservation Number Error.",
                    })

                reservation = Reservation.objects.create(
                    reservation_number=reservation_number,
                    customer_id=customer_obj,
                    ride_id=ride_obj,
                    reservation_seats=req_seats,
                    is_confirmed=False,
                    created_date=date.today(),
                )
                reservation.save()

                user_ride = UserRideDetail.objects.create(
                    ride_id=ride_obj,
                    reservation_id=reservation,
                    kilometer=kilometer,
                    price_per_km=fare_per_km,
                    payment_method_id=payment_method_obj,
                    payment_status=False,
                    fare=fare,
                    fixed_fare=FIXED_FARE,
                    pick_up_point=pick_up_point,
                    drop_off_point=drop_off_point,
                )
                user_ride.save()

                if KILOMETER_FARE:
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'reservation_number': reservation.reservation_number,
                        'Vehicle': vehicle_no_plate,
                        'Fare': user_ride.fare,
                        'price_per_km': user_ride.price_per_km,
                        'kilometer': user_ride.kilometer,
                        'Pick-up point': user_ride.pick_up_point,
                        'Drop-up point': user_ride.drop_off_point,
                        'message': 'Ride booked, but not confirmed.',
                    })

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'reservation_number': reservation.reservation_number,
                    'Vehicle': vehicle_no_plate,
                    'Fare': user_ride.fare,
                    'Pick-up point': user_ride.pick_up_point,
                    'Drop-up point': user_ride.drop_up_point,
                    'message': 'Ride booked, but not confirmed.',
                })
        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })

    @login_decorator
    @reserve_ride_decorator
    def post(self, request, **kwargs):
        try:
            vehicle_no_plate = kwargs.get('vehicle_no_plate')
            req_seats = kwargs.get('req_seats')
            pick_up_point = kwargs.get('pick_up_point')
            drop_up_point = kwargs.get('drop_up_point')
            kilometer = kwargs.get('kilometer')
            user = kwargs.get('user')
            customer = kwargs.get('customer')
            payment_method = kwargs.get('payment_method')

            ride_obj = RideBook.get_ride_obj(vehicle_no_plate)
            if not ride_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No Ride Available.'
                })

            payment_method_obj = PaymentMethod.objects.filter(payment_method=payment_method).first()
            if not payment_method_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Payment Method not exist.'
                })

            vehicle_seats = ride_obj.seats_left
            if vehicle_seats == 0:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Fully booked.'
                })

            if int(vehicle_seats) < int(req_seats):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Not enough seats in the bus'
                })

            with transaction.atomic():
                fare_object_price = fare_object(FIXED_FARE, KILOMETER_FARE)
                total_fare = fare_object_price(req_seats=req_seats, kilometer=kilometer)

                return RideBook.reserve_ride(user=user, customer=customer, vehicle_no_plate=vehicle_no_plate,
                                             req_seats=req_seats, pick_up_point=pick_up_point,
                                             ride_obj=ride_obj, drop_off_point=drop_up_point,
                                             kilometer=kilometer, fare=total_fare, payment_method=payment_method_obj)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'messsage': str(e),
            })


# work on it..
# @singleton
# Didn't check it yet.
class ConfirmRide(RideBook, generics.GenericAPIView):

    @staticmethod
    def ride_confirm_message(**kwargs):
        try:
            first_name = kwargs.get('first_name')
            phone_number = kwargs.get('phone_number')
            res_no = kwargs.get('res_no')
            vehicle_no_plate = kwargs.get('vehicle_no_plate')
            pick_up_point = kwargs.get('pick_up_point')
            drop_off_point = kwargs.get('drop_off_point')

            sawaari_message = "\nRIDE WITH SAWAARI\n"
            message_body = sawaari_message + 'Hi {}, your ride is confirmed.\nReservation Number - {}\nVehicle - {}\n' \
                                             'Pick-up-point - {}\nDrop-off-point: {}'.format(first_name, res_no,
                                                                                             vehicle_no_plate,
                                                                                             pick_up_point,
                                                                                             drop_off_point)
            sender_phone_number = SENDER_PHONE_NUMBER

            from User.twilio_verify import client

            client.messages.create(
                from_=sender_phone_number,
                body=message_body,
                to=phone_number,
            )
            return True

        except TypeError:
            return False

    @staticmethod
    @transaction.atomic
    def update_ride(vehicle_no_plate, seats_booked: int):
        try:
            with transaction.atomic():
                ride_obj = Ride.objects.filter(vehicle_id__vehicle_no_plate=vehicle_no_plate).first()
                if ride_obj:
                    seats_left = ride_obj.seats_left - int(seats_booked)
                    ride_obj.seats_left = seats_left
                    ride_obj.save()
                    return True
                return False

        except TypeError:
            return False

    @transaction.atomic
    @login_decorator
    @confirm_ride
    def post(self, request, **kwargs):
        try:
            customer = kwargs.get('customer_obj')
            reservation_number_obj = kwargs.get('reservation_number')

            with transaction.atomic():
                reservation_number_obj.is_confirmed = True
                reservation_number_obj.save()

                ride_obj = Ride.objects.filter(id=reservation_number_obj.ride_id.id).first()
                vehicle_obj = Vehicle.objects.filter(id=ride_obj.vehicle_id.id).first()

                if not ConfirmRide.update_ride(vehicle_obj.vehicle_no_plate, reservation_number_obj.reservation_seats):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Error Updating ride.',
                    })

                user_ride_obj = UserRideDetail.objects.filter(reservation_id=reservation_number_obj.id).first()
                ConfirmRide.ride_confirm_message(phone_number=customer.user.phone_number,
                                                 res_no=reservation_number_obj.reservation_number,
                                                 vehicle_no_plate=vehicle_obj.vehicle_no_plate,
                                                 pick_up_point=user_ride_obj.pick_up_point,
                                                 drop_off_point=user_ride_obj.drop_off_point,
                                                 first_name=customer.user.first_name,)

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'Reservation Number': reservation_number_obj.reservation_number,
                    'Vehicle': vehicle_obj.vehicle_no_plate,
                    'Fare': user_ride_obj.fare,
                    'price_per_km': user_ride_obj.price_per_km,
                    'kilometer': user_ride_obj.kilometer,
                    'Pick-up point': user_ride_obj.pick_up_point,
                    'Drop-up point': user_ride_obj.drop_off_point,
                    'message': 'Your ride is confirmed.'
                })

        except Exception as e:
            JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': str(e),
            })


class UserRides(generics.GenericAPIView):

    @login_decorator
    def get(self, request, data=None):
        try:
            user = data['user']
            if not user:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'User not found.',
                })

            customer = Customer.objects.filter(user=user).first()
            if not customer:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'Customer not found.',
                })

            user_reservations = Reservation.objects.filter(customer_id=customer.id)
            if not user_reservations:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'No Trips.',
                })

            user_rides = []
            for reservations in user_reservations:
                ride_details = UserRideDetail.objects.filter(reservation_id=reservations.id).first()
                user_rides.append(UserRides.rides(ride=ride_details, reservation=reservations))

            return JsonResponse({
                'status': HTTP_200_OK,
                'reservations': user_rides,
            })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_200_OK,
                'message': str(e),
            })

    @staticmethod
    def rides(**kwargs):
        ride = kwargs.get('ride')
        user_reservation = kwargs.get('reservation')

        if not ride:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': 'No Rides.',
            })

        ride_details = {
            'reservation_no': user_reservation.reservation_number,
            'pick_up_point': ride.pick_up_point,
            'drop_up_point': ride.drop_up_point,
            'seats': user_reservation.reservation_seats,
            'ride_date': ride.ride_date,
        }

        return ride_details


