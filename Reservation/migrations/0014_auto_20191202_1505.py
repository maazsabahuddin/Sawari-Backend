# Generated by Django 2.1.13 on 2019-12-02 10:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Reservation', '0013_auto_20191202_1503'),
    ]

    operations = [
        migrations.AlterField(
            model_name='stop',
            name='latitude',
            field=models.FloatField(max_length=100),
        ),
        migrations.AlterField(
            model_name='stop',
            name='longitude',
            field=models.FloatField(max_length=100),
        ),
    ]
