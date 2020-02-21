# Generated by Django 2.1.13 on 2019-10-15 07:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Reservation', '0003_reservation_created_date'),
    ]

    operations = [
        migrations.AddField(
            model_name='reservation',
            name='reservation_number',
            field=models.CharField(default=1, max_length=15, unique=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='reservation',
            name='updated_timestamp',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
