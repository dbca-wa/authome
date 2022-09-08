from django.utils.html import mark_safe
from django.contrib import admin as djangoadmin
from django.utils import timezone

from . import admin
from .. import models

class DebugLogAdmin(djangoadmin.ModelAdmin):
    color_map  = {
        models.DebugLog.CREATE_COOKIE : "#00bfff",
        models.DebugLog.UPDATE_COOKIE : "#4000ff",
        models.DebugLog.DELETE_COOKIE : "#8000ff",

        models.DebugLog.UPGRADE_SESSION : "green",
        models.DebugLog.UPGRADE_UPGRADED_SESSION : "green",
        models.DebugLog.UPGRADE_NONEXIST_SESSION : "green",

        models.DebugLog.MIGRATE_SESSION : "blue",
        models.DebugLog.MIGRATE_MIGRATED_SESSION : "blue",
        models.DebugLog.MIGRATE_NONEXIST_SESSION : "blue",
    
        models.DebugLog.MOVE_PREVIOUS_SESSION : "#008080",
        models.DebugLog.MOVE_MOVED_PREVIOUS_SESSION : "#008080",
        models.DebugLog.MOVE_NONEXIST_PREVIOUS_SESSION : "#008080",

        models.DebugLog.AUTH2_CLUSTER_NOTAVAILABLE : "#4000ff",
    
        models.DebugLog.UPGRADE_NONEXIST_UPGRADED_SESSION : "orange",
        models.DebugLog.MIGRATE_NONEXIST_MIGRATED_SESSION : "orange",
        models.DebugLog.MOVE_NONEXIST_MOVED_PREVIOUS_SESSION : "orange",

        models.DebugLog.LB_HASH_KEY_NOT_MATCH : "red",
        models.DebugLog.DOMAIN_NOT_MATCH: "coral",

        models.DebugLog.ERROR : "darkred"

    }
    list_display = ("_logtime","category","lb_hash_key","_base_session_key","session_clusterid","clusterid","email","request","_useragent")
    readonly_fields = ("_logtime","category","lb_hash_key","_base_session_key","session_clusterid","_source_session_key","clusterid","_target_session_key","email","request","useragent","_message")
    fields = readonly_fields
    ordering = ('-logtime',)
    search_fields = ["lb_hash_key","base_session_key","email" ,"request"]
    list_filter = ["category","clusterid","session_clusterid"]

    def _target_session_key(self,obj):
        if not obj or not obj.target_session_key :
            return ""
        else:
            return mark_safe("<span style='font-family: monospace'>{}</span>".format(obj.target_session_key))
    _target_session_key.short_description = "Target Session Key"

    def _source_session_key(self,obj):
        if not obj or not obj.source_session_key :
            return ""
        else:
            return mark_safe("<span style='font-family: monospace'>{}</span>".format(obj.source_session_key))
    _source_session_key.short_description = "Source Session Key"

    def _base_session_key(self,obj):
        if not obj or not obj.base_session_key :
            return ""
        else:
            return mark_safe("<span style='font-family: monospace'>{}</span>".format(obj.base_session_key))
    _base_session_key.short_description = "Base Session Key"

    def _logtime(self,obj):
        if not obj or not obj.logtime :
            return ""
        else:
            return mark_safe("<span style='color:{1}'>{0}</span>".format(timezone.localtime(obj.logtime).strftime("%Y-%m-%d %H:%M:%S.%f"),self.color_map.get(obj.category,"green")))
    _logtime.short_description = "Time"

    def _message(self,obj):
        if not obj or not obj.message :
            return ""
        else:
            return mark_safe("<pre>{}</pre>".format(obj.message))
    _message.short_description = "Message"

    def _useragent(self,obj):
        if not obj or not obj.useragent:
            return ""
        else:
            return obj.useragent[:30]
    _useragent.short_description = "User Agent"

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

