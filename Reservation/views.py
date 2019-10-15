from datetime import date
from django.db import transaction
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from rest_framework import generics
from rest_framework.authtoken.models import Token
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_404_NOT_FOUND, HTTP_200_OK
from rest_framework.views import APIView

from Payment.views import PaymentMixin
from RideSchedule.models import UserRideDetail
from RideSchedule.views import RideMixin
from User.user_token_authentication import UserMixin
from .models import Reservation, Ride
from .reservation_pattern import ReservationNumber


# class based views mae LoginRequiredMixin use rkty hen user login check krney k liye.. but in not in drf..
class BusRoute(APIView):

    # No such need pf login decorator because we're using Token authentication method. if there's a user it will be
    # logged in via token and if no token will be there means no user. it will return invalid token.
    # @method_decorator(login_required)
    def post(self, request):

        try:
            # For safety purpose. Using login decorator as well as doing it explicitly..
            # Don't remove it.
            if not request.user.is_authenticated:
                return JsonResponse({'message': 'User not authenticated'})

            from_location = request.POST['from']
            to_location = request.POST['to']

            ride_obj = self.get_vehicle(from_location, to_location)

            if ride_obj:
                ride_list = list(ride_obj)
                return JsonResponse(ride_list, safe=False)

            return JsonResponse({'message': 'No Ride available right now'})

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({'status': 'false', 'message': 'Error encountered'}, status=500)

    def get_vehicle(self, from_location, to_location):
        ride_obj = Ride.objects.filter(vehicle_id__from_loc=from_location, vehicle_id__to_loc=to_location) \
            .values('seats_left', 'vehicle_id__vehicle_no_plate')

        if ride_obj:
            return ride_obj


class BookingDetails(UserMixin, RideMixin, generics.GenericAPIView):

    def post_method_call(self, request):
        self.vehicle_no_plate = request.POST['vehicle']
        self.req_seats = request.POST['seats']
        self.pick_up_point = request.POST['from']
        self.drop_up_point = request.POST['to']
        self.kilometer = request.POST['kilometer']

    def create_session(self, request, vehicle_no_plate, req_seats, pick_up_point, drop_up_point, kilometer, fare_price, kilometer_price):
        request.session['vehicle_no_plate'] = vehicle_no_plate
        request.session['req_seats'] = req_seats
        request.session['pick_up_point'] = pick_up_point
        request.session['drop_up_point'] = drop_up_point
        request.session['kilometer'] = kilometer
        request.session['fare_price'] = fare_price
        request.session['price_per_km'] = kilometer_price

    def post(self, request):
        try:
            token = request.POST['token']
            user = self.get_user_via_token(token)

            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid token'
                })

            if not user.is_authenticated:
                return JsonResponse({
                    'status': HTTP_404_NOT_FOUND,
                    'message': 'User not authenticated'
                })

            self.post_method_call(request)

            ride_obj = self.get_ride_obj(self.vehicle_no_plate)
            if not ride_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No Vehicle found'
                })

            kilometer_price = self.kilometer_price()
            if not kilometer_price:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Server Error'
                })

            vehicle_seats = ride_obj.seats_left
            if not vehicle_seats:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Fully booked.'
                })

            if int(vehicle_seats) < int(self.req_seats):
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Not enough seats in the bus'
                })

            if int(vehicle_seats) >= int(self.req_seats):
                fare_price = self.fare_price(float(kilometer_price), float(self.kilometer))
                self.create_session(request, self.vehicle_no_plate, self.req_seats, self.pick_up_point,
                                    self.drop_up_point, self.kilometer, fare_price, kilometer_price)

                return JsonResponse({
                    'status': HTTP_200_OK,
                    'Vehicle': self.vehicle_no_plate,
                    'Fare': fare_price,
                    'price_per_km': kilometer_price,
                    'kilometer': self.kilometer,
                    'Pick-up point': self.pick_up_point,
                    'Drop-up amount': self.drop_up_point,
                })

            return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': ''})

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            return JsonResponse({'status': HTTP_404_NOT_FOUND, 'messsage': e})


class BookRide(UserMixin, PaymentMixin, RideMixin, APIView):

    @method_decorator(transaction.atomic)
    def post(self, request):

        try:
            token = request.POST['token']
            user = self.get_user_via_token(token)

            payment_method = request.POST['payment_method']
            payment_method_obj = self.check_payment_method(payment_method)
            if not payment_method_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No such payment method found.'
                })

            if not user:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'Invalid token or User not authenticated.'
                })

            customer_obj = self.get_customer(user)
            if not customer_obj:
                return JsonResponse({
                    'status': HTTP_400_BAD_REQUEST,
                    'message': 'No customer found.'
                })

            vehicle_no_plate = request.session['vehicle_no_plate']
            ride_obj = self.get_ride_obj(vehicle_no_plate)
            if not ride_obj:
                return JsonResponse({'status': HTTP_400_BAD_REQUEST, 'message': 'No Vehicle found'})

            with transaction.atomic():
                req_seats = request.session['req_seats']
                kilometer = request.session['kilometer']
                price_per_km = request.session['price_per_km']
                pick_up_point = request.session['pick_up_point']
                drop_up_point = request.session['drop_up_point']

                fare_price = self.fare_price_online(payment_method, float(price_per_km), float(kilometer))
                reservation_number = ReservationNumber().generate_new_reservation_number()

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
                    price_per_km=price_per_km,
                    payment_method_id=payment_method_obj,
                    payment_status=False,
                    total_payment=fare_price,
                    pick_up_point=pick_up_point,
                    drop_up_point=drop_up_point,
                )
                user_ride.save()
                if not self.update_ride(vehicle_no_plate, req_seats):
                    return JsonResponse({
                        'status': HTTP_404_NOT_FOUND,
                        'message': "Server Error",
                    })

            return JsonResponse({
                'status': HTTP_200_OK,
                'Reservation Number': reservation_number,
                'Vehicle': vehicle_no_plate,
                'Fare': fare_price,
                'price_per_km': price_per_km,
                'kilometer': kilometer,
                'Pick-up point': pick_up_point,
                'Drop-up point': drop_up_point,
                'message': 'Your seats are booked.'
            })

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.info(e)
            JsonResponse({
                'status': HTTP_404_NOT_FOUND,
                'message': e,
            })

