
class RideException(Exception):
    status_code = 404
    message = ""
    dev_message = ""

    def __init__(self, status_code=status_code, message=message, dev_message=dev_message):
        self.status_code = status_code
        self.message = message
        self.dev_message = dev_message


class RideNotAvailable(RideException):
    pass


class NotEnoughSeats(RideException):
    pass


class FieldMissing(RideException):
    pass


class StopNotExist(RideException):
    pass


class RideFare(RideException):
    pass
