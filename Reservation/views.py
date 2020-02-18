from datetime import date
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from rest_framework import generics
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_200_OK

from A.settings.base import FIXED_FARE, KILOMETER_FARE, SENDER_PHONE_NUMBER

from Payment.models import Pricing, PaymentMethod
# from Payment.views import PaymentMixin
from Reservation.decorator_reservation import reserve_ride_decorator, confirm_ride, cancel_ride
from RideSchedule.models import UserRideDetail
from RideSchedule.views import BusRoute
from User.decorators import login_decorator
from User.models import Customer
from User.exceptions import InvalidUsage
from .models import Reservation, Ride, Vehicle
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
                    return float(price_obj.price_per_km)
                if FIXED_FARE:
                    return float(price_obj.fixed_fare)

        except TypeError:
            return False

    @staticmethod
    def price_per_km():
        price_obj = Pricing.objects.filter().first()
        if price_obj:
            return float(price_obj.price_per_km)

    @staticmethod
    def get_ride_obj(**kwargs):
        try:
            vehicle_no_plate = kwargs.get('vehicle_no_plate')
            ride_date = kwargs.get('ride_date')

            ride_obj = Ride.objects.filter(
                vehicle_id__vehicle_no_plate=vehicle_no_plate,
                start_time__date=ride_date).first()
            if ride_obj:
                return ride_obj

            return None

        except TypeError:
            return False

    @staticmethod
    def fare_kilometer(**kwargs):
        try:
            total_seats = kwargs.get('req_seats')
            kilometer = kwargs.get('kilometer')

            fare_per_person = RideBook.db_price() * float(kilometer)
            # total_fare = fare_per_person * float(total_seats)
            return float(round(fare_per_person))

        except TypeError:
            return False

    @staticmethod
    def fare_fixed(**kwargs):
        try:
            total_seats = kwargs.get('req_seats')
            fare_per_person = RideBook.db_price()
            # total_fare = RideBook.db_price() * int(total_seats)
            return float(round(fare_per_person))

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
            fare_per_person = kwargs.get('fare_per_person')
            vehicle_no_plate = kwargs.get('vehicle_no_plate')
            payment_method_obj = kwargs.get('payment_method')
            fare_per_km = RideBook.price_per_km()
            ride_start_time = kwargs.get('ride_start_time')
            arrival_time = kwargs.get('arrival_time')

            with transaction.atomic():

                total_fare = fare_per_person * int(req_seats)
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
                    fare=total_fare,
                    fixed_fare=FIXED_FARE,
                    pick_up_point=pick_up_point,
                    drop_off_point=drop_off_point,
                    ride_status="active",
                    ride_date=ride_start_time.date(),
                    ride_arrival_time=arrival_time,
                )
                user_ride.save()

                if KILOMETER_FARE:
                    return JsonResponse({
                        'status': HTTP_200_OK,
                        'reservation_number': reservation.reservation_number,
                        'vehicle': vehicle_no_plate,
                        'fare_per_person': str(fare_per_person) + " x " + req_seats,
                        'fare': str(user_ride.fare),
                        'price_per_km': str(user_ride.price_per_km),
                        'kilometer': user_ride.kilometer,
                        'pick-up-point': user_ride.pick_up_point,
                        'drop-off-point': user_ride.drop_off_point,
                        'seats': req_seats,
                        'message': 'Ride booked, but not confirmed.',
                    })

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'reservation_number': reservation.reservation_number,
                    'vehicle': vehicle_no_plate,
                    'fare': float(fare_per_person) * float(req_seats),
                    'fare_per_person': str(fare_per_person) + " x " + req_seats,
                    'price_per_km': "",
                    'kilometer': None,
                    'pick-up-point': user_ride.pick_up_point,
                    'drop-off-point': user_ride.drop_off_point,
                    'seats': req_seats,
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
            ride_date = kwargs.get('ride_date')
            arrival_time = kwargs.get('arrival_time')

            ride_obj = RideBook.get_ride_obj(vehicle_no_plate=vehicle_no_plate, ride_date=ride_date)
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
                fare_per_person = fare_object_price(req_seats=req_seats, kilometer=kilometer)

                return RideBook.reserve_ride(user=user, customer=customer, vehicle_no_plate=vehicle_no_plate,
                                             req_seats=req_seats, pick_up_point=pick_up_point,
                                             ride_obj=ride_obj, drop_off_point=drop_up_point,
                                             kilometer=kilometer, fare_per_person=fare_per_person,
                                             payment_method=payment_method_obj, ride_start_time=ride_obj.start_time,
                                             arrival_time=arrival_time)

        except Exception as e:
            return JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'messsage': str(e),
            })


class ConfirmRide(RideBook, generics.GenericAPIView):

    @staticmethod
    def ride_confirm_message(**kwargs):
        try:
            first_name = kwargs.get('first_name')
            phone_number = kwargs.get('phone_number')
            res_no = kwargs.get('res_no')
            vehicle_no_plate = kwargs.get('vehicle_no_plate')
            pick_up_point = kwargs.get('pick_up_point')
            pick_up_time = kwargs.get('ride_arrival_time')
            drop_off_point = kwargs.get('drop_off_point')
            booked_seats = kwargs.get('booked_seats')

            sawaari_message = "RIDE WITH SAWAARI\n"
            message_body = sawaari_message + 'Hi {}, your ride is confirmed.\n' \
                                             'Reservation Number - {}\n' \
                                             'Vehicle - {}\n' \
                                             'Seats: {}\n' \
                                             'Pick-up-point: {} at {}\n' \
                                             'Drop-off-point: {}'.format(first_name, res_no, vehicle_no_plate,
                                                                         booked_seats, pick_up_point,
                                                                         pick_up_time, drop_off_point)

            from User.twilio_verify import client

            client.messages.create(
                from_=SENDER_PHONE_NUMBER,
                body=message_body,
                to=phone_number,
            )
            return True

        except Exception as e:
            raise InvalidUsage(status_code=1000, message=str(e))

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

        except Exception as e:
            print(str(e))
            return False

    @transaction.atomic
    @login_decorator
    @confirm_ride
    def post(self, request, **kwargs):
        reservation_number_obj = ''
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
                                                 first_name=customer.user.first_name,
                                                 ride_arrival_time=user_ride_obj.ride_arrival_time,
                                                 booked_seats=reservation_number_obj.reservation_seats)

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'reservation Number': reservation_number_obj.reservation_number,
                    'vehicle': vehicle_obj.vehicle_no_plate,
                    'fare_per_person': float(user_ride_obj.fare) / int(reservation_number_obj.reservation_seats),
                    'fare': float(user_ride_obj.fare),
                    'price_per_km': user_ride_obj.price_per_km,
                    'kilometer': user_ride_obj.kilometer,
                    'pick-up-point': user_ride_obj.pick_up_point,
                    'drop-off-point': user_ride_obj.drop_off_point,
                    'message': 'Your ride is confirmed.'
                })

        except InvalidUsage as e:
            if e.status_code == 1000:
                reservation_number_obj.is_confirmed = True
                reservation_number_obj.save()
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'reservation Number': reservation_number_obj.reservation_number,
                    'vehicle': vehicle_obj.vehicle_no_plate,
                    'fare_per_person': float(user_ride_obj.fare) / int(reservation_number_obj.reservation_seats),
                    'fare': float(user_ride_obj.fare),
                    'price_per_km': user_ride_obj.price_per_km,
                    'kilometer': user_ride_obj.kilometer,
                    'pick-up-point': user_ride_obj.pick_up_point,
                    'drop-off-point': user_ride_obj.drop_off_point,
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

            user_rides = []
            user_reservations = Reservation.objects.filter(customer_id=customer.id)
            if not user_reservations:
                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': user_rides,
                })

            for reservations in user_reservations:
                ride_details = UserRideDetail.objects.filter(reservation_id=reservations.id).first()
                user_rides.append(UserRides.rides(ride=ride_details, reservation=reservations))

            reverse_user_rides = user_rides[::-1]
            return JsonResponse({
                'status': HTTP_200_OK,
                'reservations': reverse_user_rides,
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

        ride_details = {}
        if not ride:
            return ride_details

        ride_details.update({
            'reservation_no': user_reservation.reservation_number,
            'pick_up_point': ride.pick_up_point,
            'pick_up_time': ride.ride_arrival_time,
            'drop_off_point': ride.drop_off_point,
            'seats': user_reservation.reservation_seats,
            'ride_date': ride.ride_date.date(),
            'ride_status': ride.ride_status,
        })

        return ride_details


class CancelRide(generics.GenericAPIView):

    @transaction.atomic
    @login_decorator
    @cancel_ride
    def post(self, request, **kwargs):
        try:
            customer = kwargs.get('customer_obj')
            reservation_number_obj = kwargs.get('reservation_number')

            with transaction.atomic():
                user_reservation_seats = reservation_number_obj.reservation_seats
                user_ride_detail_obj = UserRideDetail.objects.filter(reservation_id=reservation_number_obj.id).first()
                ride_obj = Ride.objects.filter(id=user_ride_detail_obj.ride_id.id, is_complete=False).first()

                if user_ride_detail_obj.ride_status == ("completed" or "COMPLETED" or "Completed"):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Ride completed.',
                    })

                if user_ride_detail_obj.ride_status == ("cancelled" or "Cancelled" or "CANCELLED"):
                    return JsonResponse({
                        'status': HTTP_400_BAD_REQUEST,
                        'message': 'Ride already cancelled.',
                    })

                if user_ride_detail_obj.ride_status == ("active" or "Active" or "ACTIVE"):
                    datetime_now = BusRoute.utc_to_local(timezone.now())
                    datetime_db = BusRoute.utc_to_local(user_ride_detail_obj.ride_date)

                    if datetime_now > datetime_db:
                        ride_obj.seats_left = ride_obj.seats_left + int(user_reservation_seats)
                        reservation_number_obj.is_confirmed = False
                        user_ride_detail_obj.ride_status = "RIDE CANCELLED"
                        user_ride_detail_obj.save()
                        reservation_number_obj.save()
                        ride_obj.save()

                        return JsonResponse({
                            'status': HTTP_200_OK,
                            'message': 'Ride cancelled.',
                        })

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'message': 'You can\'t cancel ride now.',
                })

        except Exception as e:
            return JsonResponse({
                'status': HTTP_400_BAD_REQUEST,
                'message': str(e),
            })
