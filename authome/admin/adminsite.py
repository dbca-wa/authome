import logging
from functools import update_wrapper

from django.apps import apps
from django.utils.text import capfirst
from django.conf import settings
from django.urls import reverse
from django.contrib import admin as djangoadmin
from django.contrib import auth
from django.urls import resolve

from .. import models as auth2_models
from .. import utils
from .. import signals
from ..cache import cache

logger = logging.getLogger(__name__)

class Auth2AdminSite(djangoadmin.AdminSite):
    def admin_view(self, view, cacheable=False):
        def _view(request, *args, **kwargs):
            utils.attach_request(request)
            try:
                if auth2_models.can_access(request.user.email,settings.AUTH2_DOMAIN,'/admin/authome/tools/'):
                    url_name = resolve(request.path_info).url_name
                    if url_name in ("index","app_list"):
                        signals.global_warning.send(sender=object,request=request)
            except:
                pass

            return view(request,*args,**kwargs)

        return super().admin_view(_view,cacheable)
        
    def _build_app_dict(self, request, label=None):
        """
        Build the app dictionary. The optional `label` parameter filters models
        of a specific app.
        """
        app_dict = {}

        if label:
            models = {
                m: m_a
                for m, m_a in self._registry.items()
                if m._meta.app_label == label
            }
        else:
            models = self._registry

        for model, model_admin in models.items():

            app_label = model._meta.app_label

            has_module_perms = model_admin.has_module_permission(request)
            if not has_module_perms:
                continue

            perms = model_admin.get_model_perms(request)

            # Check whether user has any perm for this module.
            # If so, add the module to the model_list.
            if True not in perms.values():
                continue

            info = (app_label, model._meta.model_name)
            model_dict = {
                "model": model,
                "name": capfirst(model._meta.verbose_name_plural),
                "object_name": model._meta.object_name,
                "perms": perms,
                "admin_url": None,
                "add_url": None,
            }
            if perms.get("change") or perms.get("view"):
                model_dict["view_only"] = not perms.get("change")
                try:
                    model_dict["admin_url"] = reverse(
                        "admin:%s_%s_changelist" % info, current_app=self.name
                    )
                except NoReverseMatch:
                    pass
            if perms.get("add"):
                try:
                    model_dict["add_url"] = reverse(
                        "admin:%s_%s_add" % info, current_app=self.name
                    )
                except NoReverseMatch:
                    pass

            if not model_dict.get('admin_url') or not auth2_models.can_access(request.user.email,settings.AUTH2_DOMAIN,model_dict['admin_url']):
                continue

            if app_label in app_dict:
                app_dict[app_label]['models'].append(model_dict)
            else:
                app_dict[app_label] = {
                    "name": apps.get_app_config(app_label).verbose_name,
                    "app_label": app_label,
                    "app_url": reverse(
                        "admin:app_list",
                        kwargs={"app_label": app_label},
                        current_app=self.name,
                    ),
                    "has_module_perms": has_module_perms,
                    "models": [model_dict],
                }
        #add others app
        if auth2_models.can_access(request.user.email,settings.AUTH2_DOMAIN,'/admin/authome/tools/'):
            app_label = auth2_models.UserGroup._meta.app_label
            if app_label in app_dict:
                app_dict[app_label]["models"].append({
                    'name': "{}Renew Apple Secret Key".format(" " * 3),
                    'object_name': "Renew Apple Secret Key",
                    'perms': [],
                    'admin_url': reverse("admin:renew_apple_secretkey"),
                    'add_url': None,
                })
        if settings.AUTH2_MONITORING_DIR:
            if auth2_models.can_access(request.user.email,settings.AUTH2_DOMAIN,'/admin/monitor/'):
                app_label = auth2_models.UserGroup._meta.app_label
                if app_label in app_dict:
                    if settings.AUTH2_CLUSTER_ENABLED:
                        app_dict[app_label]["models"].append({
                            'name': "{0}Auth2 Online Status".format(" " * 2),
                            'object_name': "AUTH2_ONLINE_STATUS",
                            'perms': [],
                            'admin_url': reverse("admin:auth2_onlinestatus"),
                            'add_url': None,
                        })
                        app_dict[app_label]["models"].append({
                            'name': "{1}Healthcheck({0})".format(settings.AUTH2_CLUSTERID," " * 2),
                            'object_name': "{}_Healthcheck".format(settings.AUTH2_CLUSTERID),
                            'perms': [],
                            'admin_url': reverse("admin:auth2_status",kwargs={"clusterid":settings.AUTH2_CLUSTERID}),
                            'add_url': None,
                        })
                        for cluster in cache.auth2_clusters.values():
                            app_dict[app_label]["models"].append({
                                'name': "{1}Healthcheck({0})".format(cluster.clusterid," " * 2),
                                'object_name': "{}_Healthcheck".format(cluster.clusterid),
                                'perms': [],
                                'admin_url': reverse("admin:auth2_status",kwargs={"clusterid":cluster.clusterid}),
                                'add_url': None,
                            })

                    else:
                        app_dict[app_label]["models"].append({
                            'name': "{}Healthcheck".format(" " * 2),
                            'object_name': "Healthcheck",
                            'perms': [],
                            'admin_url': reverse("admin:auth2_status"),
                            'add_url': None,
                        })


        return app_dict

admin_site = Auth2AdminSite()
#admin_site = djangoadmin.AdminSite()

#register all model admins which are already registered in django admin to auth2 admin site
registered_admins  = [(model,model_admin)for model, model_admin in djangoadmin.site._registry.items()]
for model, model_admin in registered_admins:
    djangoadmin.site.unregister(model)
    if model in (auth.models.Group,auth.models.User):
        continue
    admin_site.register(model,model_admin.__class__)


from .admin import NormalUser,SystemUser,NormalUserToken,SystemUserToken

if settings.AUTH2_CLUSTER_ENABLED:
    from .clusteradmin import Auth2ClusterAdmin
    admin_site.register(auth2_models.Auth2Cluster,Auth2ClusterAdmin)
    from .clusteradmin import (UserGroupAdmin,IdentityProviderAdmin,CustomizableUserflowAdmin,UserGroupAuthorizationAdmin,UserAdmin,UserAccessTokenAdmin,SystemUserAccessTokenAdmin)
    from .admin import (SystemUserAdmin,UserTOTPAdmin)
else:
    from .admin import (UserAdmin,SystemUserAdmin,UserGroupAuthorizationAdmin,UserGroupAdmin,UserAccessTokenAdmin,SystemUserAccessTokenAdmin,
        IdentityProviderAdmin,CustomizableUserflowAdmin,UserTOTPAdmin)

from .debugadmin import DebugLogAdmin
admin_site.register(auth2_models.DebugLog,DebugLogAdmin)

if settings.TRAFFIC_MONITOR_LEVEL > 0:
    from .monitoradmin import TrafficReportAdmin,TrafficDataAdmin
    admin_site.register(auth2_models.TrafficData,TrafficDataAdmin)
    admin_site.register(auth2_models.TrafficReport,TrafficReportAdmin)


admin_site.register(NormalUser,UserAdmin)
admin_site.register(SystemUser,SystemUserAdmin)
admin_site.register(auth2_models.UserGroupAuthorization,UserGroupAuthorizationAdmin)
admin_site.register(auth2_models.UserGroup,UserGroupAdmin)
admin_site.register(SystemUserToken,SystemUserAccessTokenAdmin)
admin_site.register(NormalUserToken,UserAccessTokenAdmin)
admin_site.register(auth2_models.IdentityProvider,IdentityProviderAdmin)
admin_site.register(auth2_models.CustomizableUserflow,CustomizableUserflowAdmin)
admin_site.register(auth2_models.UserTOTP,UserTOTPAdmin)
