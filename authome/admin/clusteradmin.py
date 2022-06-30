import logging
import traceback

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
        
class Auth2ClusterAdmin(admin.DatetimeMixin,admin.CatchModelExceptionMixin,djangoadmin.ModelAdmin):
    list_display = ('clusterid','default','endpoint','_last_heartbeat','_usergroup_lastrefreshed','_usergroupauthorization_lastrefreshed','_userflow_lastrefreshed','_idp_lastrefreshed')
    readonly_fields = ('clusterid','default','endpoint','_last_heartbeat','_usergroup_lastrefreshed','_usergroupauthorization_lastrefreshed','_userflow_lastrefreshed','_idp_lastrefreshed','modified','registered')
    fields = readonly_fields
    ordering = ('clusterid',)

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return True
