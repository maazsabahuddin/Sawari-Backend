import datetime
from Reservation.models import Reservation

prefix = "RES"
hyphen = "-"
today = datetime.date.today()


class ReservationNumber:

    @staticmethod
    def generate_new_reservation_number():
        try:
            reservation_obj = Reservation.objects.latest('id')
            if not reservation_obj:
                return None

            # Get the reservation id from the model.
            last_reservation_no = reservation_obj.reservation_number

            # Split it on "-" and returns a list.
            split_res_no = ReservationNumber.split_reservation_no(last_reservation_no)

            # Get the reservation number from the list and 1 to it.
            reservation_no = int(split_res_no) + 1

            # Complete the reservation number length by putting fine zero's.
            fill_reservation_no = ReservationNumber.fill_length_res_no(str(reservation_no))

            # Finally new reservation number by concatenating strings.
            new_reservation_no_string = ReservationNumber.reservation_no_string(fill_reservation_no)
            return new_reservation_no_string

        except Exception as e:
            return False

    @staticmethod
    def reservation_no_string(res_no):
        return prefix + hyphen + str(res_no) + hyphen + str(today.month) + str(today.year)

    @staticmethod
    def split_reservation_no(res_no):
        reservation_no = res_no.split('-')
        return reservation_no[1]

    @staticmethod
    def fill_length_res_no(res_no):
        return res_no.zfill(6)
