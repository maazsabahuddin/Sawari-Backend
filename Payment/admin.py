from django.contrib import admin
from .models import PaymentMethod, Pricing

# Register your models here.
admin.site.register(PaymentMethod)
admin.site.register(Pricing)
