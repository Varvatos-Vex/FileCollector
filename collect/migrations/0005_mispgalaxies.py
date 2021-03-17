# Generated by Django 3.1.1 on 2021-03-16 06:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('collect', '0004_filedetails_defination'),
    ]

    operations = [
        migrations.CreateModel(
            name='MispGalaxies',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uuid', models.CharField(max_length=30)),
                ('ThreatActor', models.CharField(max_length=50)),
                ('SuspectedAttribution', models.CharField(max_length=50)),
                ('Alias', models.CharField(max_length=200)),
                ('Victim', models.CharField(max_length=200)),
                ('IncidentType', models.CharField(max_length=50)),
                ('TargetSector', models.CharField(max_length=200)),
                ('Description', models.CharField(max_length=200)),
                ('Refrences', models.CharField(max_length=200)),
                ('Related', models.CharField(max_length=200)),
            ],
        ),
    ]