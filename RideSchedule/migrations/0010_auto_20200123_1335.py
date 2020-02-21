# Generated by Django 2.2.9 on 2020-01-23 08:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('RideSchedule', '0009_userridedetail_ride_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userridedetail',
            name='ride_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='userridedetail',
            name='ride_status',
            field=models.CharField(choices=[('complete', 'COMPLETE'), ('incomplete', 'INCOMPLETE'), ('cancelled', 'CANCELLED'), ('pending', 'PENDING'), ('active', 'ACTIVE')], default='pending', max_length=10),
        ),
    ]
