from django.test import TestCase


def stops_id_list(**kwargs):
    ride_stops = kwargs.get('ride_stops')
    stops_id = []
    for i in ride_stops:
        stops_id.append(int(i.id))
    return stops_id


def ride_stops_check(**kwargs):

    ride_stops = kwargs.get('ride_stops')
    pick_up_stop_id = kwargs.get('pick_up_stop_id')
    drop_off_stop_id = kwargs.get('drop_off_stop_id')

    stops_id = stops_id_list(ride_stops=ride_stops)

    result = all(item in stops_id for item in [pick_up_stop_id, drop_off_stop_id])
    if result:
        return True
    return False
