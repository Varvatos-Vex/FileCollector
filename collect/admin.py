from django.contrib import admin
from .models import ThreatActorTable
from .models import SourceTable
from .models import AliasTable
from .models import FileDetails
from .models import MispGalaxies


# Register your models here.
@admin.register(ThreatActorTable)
class ThreatActorAdmin(admin.ModelAdmin):
    list_display = ('id','ThreatActor')
    pass



@admin.register(SourceTable)
class SourceTableAdmin(admin.ModelAdmin):
    list_display = ('id','Source')
    pass


@admin.register(AliasTable)
class AliasTableAdmin(admin.ModelAdmin):
    list_display = ('id','ThreatActor','Alias')
    pass


@admin.register(FileDetails)
class FileDetailsAdmin(admin.ModelAdmin):
    list_display = ('id','User', 'date', 'ThreatActor', 'Index', 'FilePath','Defination')
    pass


@admin.register(MispGalaxies)
class FileDetailsAdmin(admin.ModelAdmin):
    list_display = ('uuid','ThreatActor', 'SuspectedAttribution', 'Alias', 'Victim', 'IncidentType','TargetSector', 'Description', 'Refrences','Related')
    pass