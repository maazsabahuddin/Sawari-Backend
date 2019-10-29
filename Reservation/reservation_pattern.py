import datetime
from Reservation.models import Reservation

prefix = "RES"
dash = "-"
today = datetime.date.today()


class ReservationNumber:

    def generate_new_reservation_number(self):
        try:
            reservation_obj = Reservation.objects.latest('id')
            if not reservation_obj:
                return None
            last_reservation_no = reservation_obj.reservation_number
            split_res_no = self.split_reservation_no(last_reservation_no)
            reservation_no = int(split_res_no) + 1
            fill_reservation_no = self.fill(str(reservation_no))
            new_reservation_no_string = self.reservation_no_string(fill_reservation_no)
            return new_reservation_no_string

        except Exception as e:
            return False

    def fill(self, res_no):
        return res_no.zfill(6)

    def reservation_no_string(self, res_no):
        return prefix + dash + str(res_no) + dash + str(today.month) + str(today.year)

    def split_reservation_no(self, res_no):
        reservation_no = res_no.split('-')
        return reservation_no[1]

    def length_res_no(self, res_no):
        return res_no.zfill(6)
