import logging
from functools import update_wrapper

from django.apps import apps
from django.utils.text import capfirst
from django.conf import settings
from django.urls import reverse
from django.contrib import admin as djangoadmin
from django.contrib import auth

from .. import models
from .. import utils

class Auth2AdminSite(djangoadmin.AdminSite):
    def admin_view(self, view, cacheable=False):
        def _view(request, *args, **kwargs):
            utils.attach_request(request)
            return view(request,*args,**kwargs)

        return super().admin_view(_view,cacheable)
        
    def _build_app_dict(self, request, label=None):
        """
        Build the app dictionary. The optional `label` parameter filters models
        of a specific app.
        """
        app_dict = {}

        if label:
            registered_models = {
                m: m_a for m, m_a in self._registry.items()
                if m._meta.app_label == label
            }
        else:
            registered_models = self._registry

        for model, model_admin in registered_models.items():
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
                'name': capfirst(model._meta.verbose_name_plural),
                'object_name': model._meta.object_name,
                'perms': perms,
                'admin_url': None,
                'add_url': None,
            }
            if perms.get('change') or perms.get('view'):
                model_dict['view_only'] = not perms.get('change')
                try:
                    model_dict['admin_url'] = reverse('admin:%s_%s_changelist' % info, current_app=self.name)
                except NoReverseMatch:
                    pass
            if perms.get('add'):
                try:
                    model_dict['add_url'] = reverse('admin:%s_%s_add' % info, current_app=self.name)
                except NoReverseMatch:
                    pass

            if not model_dict.get('admin_url') or not models.can_access(request.user.email,settings.AUTH2_DOMAIN,model_dict['admin_url']):
                continue

            if app_label in app_dict:
                app_dict[app_label]['models'].append(model_dict)
            else:
                app_dict[app_label] = {
                    'name': apps.get_app_config(app_label).verbose_name,
                    'app_label': app_label,
                    'app_url': reverse(
                        'admin:app_list',
                        kwargs={'app_label': app_label},
                        current_app=self.name,
                    ),
                    'has_module_perms': has_module_perms,
                    'models': [model_dict],
                }

        if label:
            return app_dict.get(label)
        return app_dict

admin_site = Auth2AdminSite()

#register all model admins which are already registered in django admin to auth2 admin site
for model, model_admin in djangoadmin.site._registry.items():
    if model in (auth.models.Group,auth.models.User):
        continue
    admin_site._registry[model] = model_admin


from .admin import NormalUser,SystemUser,NormalUserToken,SystemUserToken

if settings.AUTH2_CLUSTER_ENABLED:
    from .clusteradmin import Auth2ClusterAdmin
    admin_site.register(models.Auth2Cluster,Auth2ClusterAdmin)
    from .clusteradmin import (UserGroupAdmin,IdentityProviderAdmin,CustomizableUserflowAdmin,UserGroupAuthorizationAdmin,UserAdmin,UserAccessTokenAdmin,SystemUserAccessTokenAdmin)
    from .admin import (SystemUserAdmin,UserTOTPAdmin)
else:
    from .admin import (UserAdmin,SystemUserAdmin,UserGroupAuthorizationAdmin,UserGroupAdmin,UserAccessTokenAdmin,SystemUserAccessTokenAdmin,
        IdentityProviderAdmin,CustomizableUserflowAdmin,UserTOTPAdmin)

if settings.DEBUG:
    from .debugadmin import DebugLogAdmin
    admin_site.register(models.DebugLog,DebugLogAdmin)

if settings.TRAFFIC_MONITOR_LEVEL > 0:
    from .monitoradmin import TrafficReportAdmin,TrafficDataAdmin
    admin_site.register(models.TrafficData,TrafficDataAdmin)
    admin_site.register(models.TrafficReport,TrafficReportAdmin)


admin_site.register(NormalUser,UserAdmin)
admin_site.register(SystemUser,SystemUserAdmin)
admin_site.register(models.UserGroupAuthorization,UserGroupAuthorizationAdmin)
admin_site.register(models.UserGroup,UserGroupAdmin)
admin_site.register(SystemUserToken,SystemUserAccessTokenAdmin)
admin_site.register(NormalUserToken,UserAccessTokenAdmin)
admin_site.register(models.IdentityProvider,IdentityProviderAdmin)
admin_site.register(models.CustomizableUserflow,CustomizableUserflowAdmin)
admin_site.register(models.UserTOTP,UserTOTPAdmin)
