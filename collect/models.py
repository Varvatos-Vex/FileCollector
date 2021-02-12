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
    FilePath = models.FileField(upload_to='Files/')