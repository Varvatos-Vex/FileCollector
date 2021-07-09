from django.db import models

# Create your models here.

class ThreatActorTable(models.Model):
    ThreatActor = models.CharField(max_length=30)


class SourceTable(models.Model):
    Source = models.CharField(max_length=30)

#----------------Alease Details-----------------------
class AliasTable(models.Model):
    ThreatActor = models.CharField(max_length=30)
    Alias = models.CharField(max_length=300)

#----------------File Inpput Details-----------------------
class FileDetails(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    ThreatActor =  models.CharField(max_length=30)
    User =  models.CharField(max_length=30)
    Index =  models.CharField(max_length=30)
    Defination =  models.CharField(max_length=1200)
    FilePath = models.FileField(upload_to='Files/')


class MispGalaxies(models.Model):
    uuid = models.CharField(max_length=30)
    ThreatActor =  models.CharField(max_length=50)
    SuspectedAttribution =  models.CharField(max_length=50)
    Alias =  models.CharField(max_length=200)
    Victim =  models.CharField(max_length=200)
    IncidentType =  models.CharField(max_length=50)
    TargetSector =  models.CharField(max_length=200)
    Description =  models.CharField(max_length=200)
    Refrences =  models.CharField(max_length=200)
    Related =  models.CharField(max_length=200)

from django.utils import timezone
class AVModel(models.Model):
    date = models.DateTimeField(auto_now_add=True)
    FilePath = models.FileField(upload_to='AV/')



class TActorModel(models.Model):
    ThreatActor =  models.CharField(max_length=50)
    ThreatActorAlias =  models.CharField(max_length=500)