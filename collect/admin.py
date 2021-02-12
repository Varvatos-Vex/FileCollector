from django.contrib import admin
from .models import ThreatActorTable
from .models import SourceTable
from .models import AliasTable
from .models import FileDetails


# Register your models here.
@admin.register(ThreatActorTable)
class ThreatActorAdmin(admin.ModelAdmin):
    pass



@admin.register(SourceTable)
class SourceTableAdmin(admin.ModelAdmin):
    pass


@admin.register(AliasTable)
class AliasTableAdmin(admin.ModelAdmin):
    pass


@admin.register(FileDetails)
class FileDetailsAdmin(admin.ModelAdmin):
    pass
