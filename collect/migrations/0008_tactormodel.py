# Generated by Django 3.1.1 on 2021-07-09 06:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('collect', '0007_auto_20210318_0639'),
    ]

    operations = [
        migrations.CreateModel(
            name='TActorModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ThreatActor', models.CharField(max_length=50)),
                ('ThreatActorAlias', models.CharField(max_length=500)),
            ],
        ),
    ]
