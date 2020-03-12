
class Payment(Exception):
    status_code = 404
    message = ""

    def __init__(self, status_code=status_code, message=message):
        self.status_code = status_code
        self.message = message


class PaymentMethodException(Payment):
    pass
