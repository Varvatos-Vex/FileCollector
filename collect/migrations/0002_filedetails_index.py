# Generated by Django 3.1.1 on 2021-02-17 06:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('collect', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='filedetails',
            name='Index',
            field=models.CharField(default='', max_length=30),
            preserve_default=False,
        ),
    ]
