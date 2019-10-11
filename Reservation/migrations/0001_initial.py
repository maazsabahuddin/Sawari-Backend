# Generated by Django 2.1.13 on 2019-10-11 12:17

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Reservation',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('reservation_seats', models.IntegerField()),
                ('is_confirmed', models.BooleanField(default=False)),
            ],
        ),
        migrations.CreateModel(
            name='Ride',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_time', models.DateTimeField(blank=True, null=True)),
                ('end_time', models.DateTimeField(blank=True, null=True)),
                ('route', models.CharField(max_length=256)),
                ('seats_left', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Vehicle',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('vehicle_no_plate', models.CharField(max_length=10)),
                ('brand', models.CharField(blank=True, max_length=20)),
                ('max_seats', models.IntegerField()),
                ('from_loc', models.CharField(default='K', max_length=255)),
                ('to_loc', models.CharField(default='L', max_length=255)),
            ],
        ),
    ]
