from math import cos, asin, sqrt


def closest(data, v):
    return min(data, key=lambda p: distance(v['lat'], v['lon'], p['lat'], p['lon']))


tempDataList = [{'lat': 39.7612992, 'lon': -86.1519681},
                {'lat': 39.762241,  'lon': -86.158436 },
                {'lat': 39.7622292, 'lon': -86.1578917}, ]


# It returns the result in Kilometer.
def distance(lat1, lon1, lat2, lon2):
    p = 0.017453292519943295
    a = 0.5 - cos((lat2-lat1)*p)/2 + cos(lat1*p)*cos(lat2*p) * (1-cos((lon2-lon1)*p)) / 2
    return 12742 * asin(sqrt(a))


v = {'lat': 39.7622290, 'lon': -86.1519750}
# print(closest(tempDataList, v))
# print(tempDataList[0]['lat'], tempDataList[0]['lon'])
print(distance(v['lat'], v['lon'], tempDataList[0]['lat'], tempDataList[0]['lon']))
