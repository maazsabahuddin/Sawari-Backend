# Generated by Django 2.1.13 on 2019-12-10 07:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Reservation', '0014_auto_20191202_1505'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='stop',
            name='route_ids',
        ),
        migrations.AddField(
            model_name='route',
            name='route_ids',
            field=models.ManyToManyField(related_name='route_stops', to='Reservation.Stop'),
        ),
    ]
