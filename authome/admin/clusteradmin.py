import logging
import traceback
import threading

from django.http import HttpResponseRedirect
from django.utils import timezone
from django.conf import settings
from django.contrib import messages, auth
from django.core.exceptions import ObjectDoesNotExist
from django.utils.html import mark_safe
from django.templatetags.static import static
from django.db.models import Q
from django.contrib.admin.views.main import ChangeList
from django.urls import reverse
from django.template.response import TemplateResponse
from django.contrib import admin as djangoadmin
from django.urls import path

from .. import models
from .. import forms
from ..cache import cache,get_defaultcache
from . import admin
from .. import utils

logger = logging.getLogger(__name__)


defaultcache = get_defaultcache()

class SyncConfigChangeMixin(object):
    def __init__(self, model, admin_site):
        super().__init__(model,admin_site)
        self.extra_tools = [("sync_changes",'sync_config')]
    
    def get_urls(self):
        urls = super().get_urls()
        info = self.model._meta.app_label, self.model._meta.model_name
        urls.insert(0,path('sync_config/', self.sync_config, name='%s_%s_sync_config' % info))
        return urls

    def sync_config(self,request):
        obj = self.model.objects.all().only("id","modified").order_by("-modified").first()
        if not obj:
            #no data, no need to sync
            self.message_user(
                request, 
                "Can't find any data in {}, no need to synchronize among clusters".format(self.model.__name__)
            )
            return HttpResponseRedirect(reverse(changelist_url_name))
        current_cluster_changed = False
        model_change_cls = self.model.get_model_change_cls()
        try:
            modified = timezone.localtime(obj.modified)
        except:
            pass
        if modified:
            try:
                last_refreshed = defaultcache.get(model_change_cls.key)
                if not last_refreshed or last_refreshed <= modified:
                    #current cluster's cache is outdated
                    model_change_cls.change(localonly=True)
                    current_cluster_changed = True
            except Exception as ex:
                self.message_user(
                    request, 
                    "Failed to synchronize the changes to current cluster{}.{}".format(settings.AUTH2_CLUSTERID,str(ex)),
                    level=messages.ERROR
                )

        changed_clusters,not_changed_clusters,failed_clusters = cache.config_changed(self.model,modified) 
        if current_cluster_changed:
            changed_clusters.insert(0,cache.current_auth2_cluster)
        else:
            not_changed_clusters.insert(0,cache.current_auth2_cluster)

        if failed_clusters:
            message = "Failed to send sync event for model({}) to all clusters.".format(self.model.__name__)
        else:
            message = "Succeed to send sync event for model({}) to all clusters.".format(self.model.__name__)
        if changed_clusters:
            message = "{}, succeed clusters are {}".format(message,[c.clusterid for c in changed_clusters])
        if not_changed_clusters:
            message = "{}, already up_to_date clusters are {}".format(message,[c.clusterid for c in not_changed_clusters])
        if failed_clusters:
            self.message_user(
                request, 
                "{},failed clusters are {}".format(message,["{}:{}".format(c,str(ex)) for c,ex in failed_clusters]),
                level=messages.ERROR
            )
        else:
            self.message_user(
                request, 
                message
            )
        changelist_url_name = 'admin:{}_{}_changelist'.format(self.model._meta.app_label,self.model._meta.model_name)
        return HttpResponseRedirect(reverse(changelist_url_name))

class SyncObjectChangeMixin(object):
    
    def get_actions(self, request):
        actions = super().get_actions(request)
        actions["sync_change"] = self.get_action("sync_change")
        return actions
        

    def _sync_change(self,objids):
        return None

    def sync_change(self,request,queryset):
        objs = [o for o in queryset]
        objids = ",".join(str(o.id) for o in objs)
        objnames = ",".join(str(o) for o in objs)
        changed_clusters,not_changed_clusters,failed_clusters = self._sync_change(objids)

        if failed_clusters:
            message = "Failed to send sync event for {}({}) to all clusters.".format(self.model.__name__,objnames)
        else:
            message = "Succeed to send sync event for {}({}) to all clusters.".format(self.model.__name__,objnames)
        if changed_clusters:
            message = "{}, succeed clusters are {}".format(message,[c.clusterid for c in changed_clusters])
        if not_changed_clusters:
            message = "{}, already up_to_date clusters are {}".format(message,[c.clusterid for c in not_changed_clusters])
        if failed_clusters:
            self.message_user(
                request, 
                "{},failed clusters are {}".format(message,["{}:{}".format(c,str(ex)) for c,ex in failed_clusters]),
                level=messages.ERROR
            )
        else:
            self.message_user(
                request, 
                message
            )
        changelist_url_name = 'admin:{}_{}_changelist'.format(self.model._meta.app_label,self.model._meta.model_name)
        return HttpResponseRedirect(reverse(changelist_url_name))
    sync_change.short_description = 'Sync Change'


class UserGroupAdmin(SyncConfigChangeMixin,admin.UserGroupAdmin):
    pass

class UserGroupAuthorizationAdmin(SyncConfigChangeMixin,admin.UserGroupAuthorizationAdmin):
    pass
        
class IdentityProviderAdmin(SyncConfigChangeMixin,admin.IdentityProviderAdmin):
    pass

class CustomizableUserflowAdmin(SyncConfigChangeMixin,admin.CustomizableUserflowAdmin):
    pass
        
class UserAdmin(SyncObjectChangeMixin,admin.UserAdmin):
    def _sync_change(self,objids):
        return cache.users_changed(objids,True)
        
class UserAccessTokenAdmin(SyncObjectChangeMixin,admin.UserAccessTokenAdmin):
    def _sync_change(self,objids):
        return cache.usertokens_changed(objids,True)
        
class SystemUserAccessTokenAdmin(SyncObjectChangeMixin,admin.SystemUserAccessTokenAdmin):
    def _sync_change(self,objids):
        return cache.usertokens_changed(objids,True)
        
class Auth2ClusterAdmin(admin.DeleteMixin,admin.DatetimeMixin,admin.CatchModelExceptionMixin,djangoadmin.ModelAdmin):
    list_display = ('clusterid','_running_status','default','endpoint','_last_heartbeat','_usergroup_status','_usergroupauthorization_status','_userflow_status','_idp_status')
    readonly_fields = ('clusterid','_running_status','default','endpoint','_last_heartbeat','_usergroup_status','_usergroup_lastrefreshed','_usergroupauthorization_status','_usergroupauthorization_lastrefreshed','_userflow_status','_userflow_lastrefreshed','_idp_status','_idp_lastrefreshed','modified','registered')
    fields = readonly_fields
    ordering = ('clusterid',)

    def _get_cache_status(self,obj,key,f_name=None,default="N/A"):
        try:
            return f_name(obj.cache_status.get(key,default)) if f_name else obj.cache_status.get(key,default)
        except AttributeError as ex:
            if obj.clusterid == settings.AUTH2_CLUSTERID:
                data = {}
                for cls in (models.UserGroup,models.UserGroupAuthorization,models.CustomizableUserflow,models.IdentityProvider):
                    data[cls.__name__] = [cls.cache_status(),utils.format_datetime(cls.get_next_refreshtime())]
                data["running"] = "Running"
                obj.cache_status = data
            else:
                try:
                    obj.cache_status = cache.get_model_cachestatus(obj.clusterid)
                    obj.cache_status["running"] = "Running"
                except Exception as ex:
                    obj.cache_status = {"running":str(ex)}
            return f_name(obj.cache_status.get(key,default)) if f_name else obj.cache_status.get(key,default)
                
    def _running_status(self,obj):
        if not obj :
            return ""
        else:
            return self._get_cache_status(obj,"running")
    _running_status.short_description = "Running status"


    f_cache_status_name = staticmethod(lambda k:mark_safe("<div>{}<br><span style='font-style:italic;font-size:10px'>({})</span></div>".format(models.CACHE_STATUS_NAME.get(k[0],k[0]),k[1]) if k[0] != "N/A" else "N/A" ))
    def _userflow_status(self,obj):
        if not obj :
            return ""
        else:
            return self._get_cache_status(obj,models.CustomizableUserflow.__name__,f_name=self.f_cache_status_name,default=("N/A",""))
    _userflow_status.short_description = "UserFlow Status"

    def _usergroup_status(self,obj):
        if not obj :
            return ""
        else:
            return self._get_cache_status(obj,models.UserGroup.__name__,f_name=self.f_cache_status_name,default=("N/A",""))
    _usergroup_status.short_description = "UserGroup Status"

    def _usergroupauthorization_status(self,obj):
        if not obj :
            return ""
        else:
            return self._get_cache_status(obj,models.UserGroupAuthorization.__name__,f_name=self.f_cache_status_name,default=("N/A",""))
    _usergroupauthorization_status.short_description = "UserGroup Status"


    def _idp_status(self,obj):
        if not obj :
            return ""
        else:
            return self._get_cache_status(obj,models.IdentityProvider.__name__,f_name=self.f_cache_status_name)
    _idp_status.short_description = "IDP Status"

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return True
