# Generated by Django 2.1.13 on 2019-10-17 10:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Reservation', '0004_auto_20191015_1256'),
    ]

    operations = [
        migrations.AlterField(
            model_name='reservation',
            name='reservation_number',
            field=models.CharField(max_length=20, unique=True),
        ),
    ]
