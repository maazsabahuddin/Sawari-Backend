# Generated by Django 2.1.13 on 2019-10-11 12:17

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('Reservation', '0001_initial'),
        ('Payment', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserRideDetail',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('kilometer', models.IntegerField()),
                ('price_per_km', models.CharField(max_length=5)),
                ('payment_status', models.BooleanField(default=False)),
                ('total_payment', models.IntegerField()),
                ('pick_up_point', models.CharField(blank=True, max_length=256)),
                ('drop_up_point', models.CharField(blank=True, max_length=256)),
                ('ride_date', models.DateField(auto_now_add=True)),
                ('payment_method_id', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='Payment.PaymentMethod')),
                ('reservation_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Reservation.Reservation')),
                ('ride_id', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='Reservation.Ride')),
            ],
        ),
    ]
