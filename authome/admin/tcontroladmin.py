import logging

from django.contrib import admin as djangoadmin

from .admin import DatetimeMixin,PermissionCheckMixin,CacheableListTitleMixin,CatchModelExceptionMixin
from .. import models
from .. import forms

logger = logging.getLogger(__name__)

class TrafficControlLocationInline(DatetimeMixin,djangoadmin.TabularInline):
    model = models.TrafficControlLocation
    #form = forms.WebAppRequestForm
    fields = ("method","domain","location","_modified")
    readonly_fields = ["_modified"]


class TrafficControlAdmin(PermissionCheckMixin,CacheableListTitleMixin,DatetimeMixin,CatchModelExceptionMixin,djangoadmin.ModelAdmin):
    list_display = ('name','enabled','est_processtime','buckettime','concurrency','timeout','block','iplimit','iplimitperiod','userlimit','userlimitperiod','_modified','_created')
    readonly_fields = ('_modified','_created')
    fields = ('name','enabled','est_processtime','buckettime','concurrency','timeout',"block",'iplimit','iplimitperiod','userlimit','userlimitperiod','exempt_include','exempt_groups','_modified','_created')
    ordering = ('name',)
    search_fields=("email",)
    form = forms.TrafficControlForm

    object_change_url_name = 'admin:{}_{}_change'.format(models.TrafficControl._meta.app_label,models.TrafficControl._meta.model_name)
    object_delete_url_name = 'admin:{}_{}_delete'.format(models.TrafficControl._meta.app_label,models.TrafficControl._meta.model_name)

    inlines = [TrafficControlLocationInline]

