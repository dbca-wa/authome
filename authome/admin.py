import logging
import traceback

from django.apps import apps
from django.utils.text import capfirst
from django.contrib import admin as djangoadmin
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

from . import models
from . import forms

logger = logging.getLogger(__name__)

class Auth2AdminSite(djangoadmin.AdminSite):
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


class CacheableChangeList(ChangeList):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        logger.debug("Refresh the model({}) data if required".format(self.model))
        self.model.refresh_cache_if_required()

        if self.model.is_outdated():
            self.title = "{}(Cache is outdated, latest refresh time is {}, next refresh time is {})".format(
                self.title,
                timezone.localtime(self.model.get_cachetime()).strftime("%Y-%m-%d %H:%M:%S") if self.model.get_cachetime() else "None",
                timezone.localtime(self.model.get_next_refreshtime()).strftime("%Y-%m-%d %H:%M:%S") if self.model.get_next_refreshtime() else "None"
            )
        else:
            self.title = "{}(Cache is up-to-date, latest refresh time is {}, next refresh time is {})".format(
                self.title,
                timezone.localtime(self.model.get_cachetime()).strftime("%Y-%m-%d %H:%M:%S") if self.model.get_cachetime() else "None",
                timezone.localtime(self.model.get_next_refreshtime()).strftime("%Y-%m-%d %H:%M:%S") if self.model.get_next_refreshtime() else "None"
            )


class CacheableListTitleMixin(object):
    def get_changelist(self, request, **kwargs):
        """
        Return the ChangeList class for use on the changelist page.
        """
        return CacheableChangeList


class DatetimeMixin(object):
    def _modified(self,obj):
        if not obj or not obj.modified :
            return ""
        else:
            return timezone.localtime(obj.modified).strftime("%Y-%m-%d %H:%M:%S")
    _modified.short_description = "Modified"

    def _created(self,obj):
        if not obj or not obj.created :
            return ""
        else:
            return timezone.localtime(obj.created).strftime("%Y-%m-%d %H:%M:%S")
    _created.short_description = "Created"

    def _last_login(self,obj):
        if not obj or not obj.last_login :
            return ""
        else:
            return timezone.localtime(obj.last_login).strftime("%Y-%m-%d %H:%M:%S")
    _last_login.short_description = "Last Login"

    def _date_joined(self,obj):
        if not obj or not obj.date_joined :
            return ""
        else:
            return timezone.localtime(obj.date_joined).strftime("%Y-%m-%d %H:%M:%S")
    _date_joined.short_description = "Date Joined"

    def _last_verified(self,obj):
        if not obj or not obj.last_verified :
            return ""
        else:
            return timezone.localtime(obj.last_verified).strftime("%Y-%m-%d %H:%M:%S")
    _date_joined.short_description = "Last Verified"




class UserGroupsMixin(object):
    group_change_url_name = 'admin:{}_{}_change'.format(models.UserGroup._meta.app_label,models.UserGroup._meta.model_name)
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        self._request = request
        return qs

    def _usergroups(self,obj):
        if not obj :
            return ""
        else:
            usergroups,usergroupnames = models.UserGroup.find_groups(obj.email,cacheable=False)
            result = None
            for group in usergroups:
                url = reverse(self.group_change_url_name, args=(group.id,))
                if self._request and models.can_access(self._request.user.email,settings.AUTH2_DOMAIN,url):
                    if result:
                        result = "{0} , <A style='margin-left:5px' href='{2}'>{1}</A>".format(result,group.name,url)
                    else:
                        result = "<A href='{1}'>{0}</A>".format(group.name,url)
                else:
                    if result:
                        result = "{0} , {1}".format(result,group.name)
                    else:
                        result = group.name

            return mark_safe("{} ({})".format(result,usergroupnames))
    _usergroups.short_description = "User Groups"

    def _usergroupnames(self,obj):
        if not obj :
            return ""
        else:
            return models.UserGroup.find_groups(obj.email,cacheable=False)[1]
    _usergroupnames.short_description = "User Group Names"

class UserAuthorizationCheckMixin(object):
    def check_authorization(self,request, queryset):
        users = queryset.values_list("email",flat=True)

        users = ",".join(users) if users else ""
        return TemplateResponse(request, "authome/check_authorization.html", {"users":users,"opts":self.model._meta})


    check_authorization.short_description = 'Check Authorization'


class NormalUser(models.User):
    objects = models.NormalUserManager()
    class Meta:
        proxy = True
        verbose_name="User"
        verbose_name_plural="{}Users".format(" " * 8)


class UserAdmin(UserAuthorizationCheckMixin,UserGroupsMixin,DatetimeMixin,auth.admin.UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name','is_active', 'is_staff','last_idp','_last_login')
    list_filter = ( 'is_superuser',)
    readonly_fields = ("_last_login","_date_joined","username","first_name","last_name","is_staff","_email","_usergroups","last_idp")
    fieldsets = (
        (None, {'fields': ('_email', )}),
        ('Personal info', {'fields': ('username','first_name', 'last_name',"_usergroups")}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', ),
        }),
        ('Important dates', {'fields': ('last_idp','_last_login', '_date_joined')}),
    )

    change_form_template = 'admin/change_form.html'
    form = forms.UserCreateForm
    actions = ["check_authorization"]

    def _email(self,obj):
        if not obj :
            return ""
        else:
            return obj.email
    _email.short_description = "Email"

    def has_add_permission(self, request, obj=None):
        return False
admin_site.register(NormalUser,UserAdmin)

class SystemUser(models.User):
    objects = models.SystemUserManager()
    class Meta:
        proxy = True
        verbose_name="System User"
        verbose_name_plural="{}System Users".format(" " * 6)


class SystemUserAdmin(UserGroupsMixin,DatetimeMixin,auth.admin.UserAdmin):
    list_display = ('username', 'email', 'is_active', '_usergroups','last_idp','_last_login')
    list_filter = ("is_active",)
    add_form_template = 'admin/change_form.html'
    change_form_template = 'admin/change_form.html'
    add_form = forms.SystemUserCreateForm
    form = forms.UserCreateForm
    readonly_fields = ("_last_login","_date_joined","username","_email","_usergroups")
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ("email",)
        }),
    )
    fieldsets = (
        (None, {'fields': ('_email', "_usergroups")}),
        ('Personal info', {'fields': ('username',)}),
        ('Permissions', {
            'fields': ('is_active', ),
        }),
        ('Important dates', {'fields': ('_last_login', '_date_joined')}),
    )

    object_change_url_name = 'admin:{}_{}_change'.format(SystemUser._meta.app_label,SystemUser._meta.model_name)
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,))):
            return qs
        else:
            ids = [o.id for o in qs.only("id") if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(o.id,)))] 
            return SystemUser.objects.filter(id__in=ids)

    def _email(self,obj):
        if not obj :
            return ""
        else:
            return obj.email
    _email.short_description = "Email"

    def has_add_permission(self, request, obj=None):
        return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,)))

    def has_delete_permission(self, request, obj=None):
        return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,)))


admin_site.register(SystemUser,SystemUserAdmin)


class UserGroupAdmin(CacheableListTitleMixin,DatetimeMixin,djangoadmin.ModelAdmin):
    list_display = ('name','groupid','parent_group','users','excluded_users','identity_provider','_session_timeout','_modified','_created')
    readonly_fields = ('_modified',)
    fields = ('name','groupid','parent_group','users','excluded_users','identity_provider','session_timeout','_modified')
    ordering = ('parent_group','name',)
    form = forms.UserGroupForm

    object_change_url_name = 'admin:{}_{}_change'.format(models.UserGroup._meta.app_label,models.UserGroup._meta.model_name)
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,))):
            return qs
        else:
            qs = qs.only("id")
            ids = [o.id for o in qs if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(o.id,)))] 
            return models.UserGroup.objects.filter(id__in=ids)

    def _session_timeout(self,obj):
        if not obj :
            return ""
        else:
            result = obj.sessiontimeout
            if result == 0:
                return ""
            else:
                return result
    _session_timeout.short_description = "Session Timeout"

    def has_add_permission(self, request, obj=None):
        return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,)))

    def has_delete_permission(self, request, obj=None):
        return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,)))

admin_site.register(models.UserGroup,UserGroupAdmin)


class UserGroupAuthorizationAdmin(CacheableListTitleMixin,DatetimeMixin,djangoadmin.ModelAdmin):
    list_display = ('usergroup','domain','paths','excluded_paths','_modified','_created')
    readonly_fields = ('_modified',)
    fields = ('usergroup','domain','paths','excluded_paths','_modified')
    ordering = ('usergroup',models.sortkey_c.asc())
    form = forms.UserGroupAuthorizationForm

    object_change_url_name = 'admin:{}_{}_change'.format(models.UserGroupAuthorization._meta.app_label,models.UserGroupAuthorization._meta.model_name)
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,))):
            return qs
        else:
            qs = qs.only("id")
            ids = [o.id for o in qs if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(o.id,)))] 
            return models.UserGroupAuthorization.objects.filter(id__in=ids)

    def has_add_permission(self, request, obj=None):
        return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,)))

    def has_delete_permission(self, request, obj=None):
        return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,)))

admin_site.register(models.UserGroupAuthorization,UserGroupAuthorizationAdmin)


class UserAuthorizationAdmin(CacheableListTitleMixin,DatetimeMixin,djangoadmin.ModelAdmin):
    list_display = ('user','domain','paths','excluded_paths','_modified','_created')
    readonly_fields = ('_modified',)
    fields = ('user','domain','paths','excluded_paths','_modified')
    ordering = ('user',models.sortkey_c.asc())
    form = forms.UserAuthorizationForm


class TokenStatusFilter(djangoadmin.SimpleListFilter):
    # Human-readable title which will be displayed in the
    # right admin sidebar just above the filter options.
    title = 'Token Status'

    # Parameter for the filter that will be used in the URL query.
    parameter_name = 'token_status'

    def lookups(self, request, model_admin):
        """
        Returns a list of tuples. The first element in each
        tuple is the coded value for the option that will
        appear in the URL query. The second element is the
        human-readable name for the option that will appear
        in the right sidebar.
        """
        if settings.USER_ACCESS_TOKEN_WARNING:
            return [("all_token","All Token"),('valid_token','Valid Token'),('soon_expired_token',"Soon Expired Token"),("expired_token","Expired Token")]
        else:
            return [("all_token","All Token"),('valid_token','Valid Token'),("Expired_token","Expired Token")]

    def queryset(self, request, queryset):
        """
        Returns the filtered queryset based on the value
        provided in the query string and retrievable via
        `self.value()`.
        """
        # Compare the requested value (either '80s' or '90s')
        # to decide how to filter the queryset.
        val = self.value()
        if not val:
            return queryset
        elif val == 'all_token':
            return queryset.filter(token__isnull=False,token__token__isnull=False)
        elif val == "valid_token":
            return queryset.filter(token__isnull=False,token__enabled=True,token__token__isnull=False).filter(Q(token__expired__isnull=True) | Q(token__expired__gte=timezone.localdate()))
        elif val == "soon_expired_token":
            return queryset.filter(token__isnull=False,token__token__isnull=False,token__expired__gte=timezone.localdate(),token__expired__lt=timezone.localdate() + settings.USER_ACCESS_TOKEN_WARNING)
        elif val == "expired_token":
            return queryset.filter(token__isnull=False,token__token__isnull=False,token__expired__lt=timezone.localdate())
        else:
            return queryset

class SystemUserToken(models.User):
    objects = models.SystemUserManager()
    class Meta:
        proxy = True
        verbose_name="System User"
        verbose_name_plural="{}System User Tokens".format(" " * 5)

class NormalUserToken(models.User):
    objects = models.NormalUserManager()
    class Meta:
        proxy = True
        verbose_name="System User"
        verbose_name_plural="{}User Tokens".format(" " * 7)


class AccessTokenAdmin(DatetimeMixin,auth.admin.UserAdmin):
    list_display = ('email','last_name','first_name','_token_enabled','_token_short','_token_created','_token_expired')
    readonly_fields = ('email','last_name','first_name','_token_enabled','_token','_token_created','_token_expired')
    ordering = ('email',)
    change_form_template = 'admin/change_form.html'
    actions = ['enable_token','disable_token'] + ['create_{}days_token'.format(o) if o > 0 else 'create_permenent_token' for o in settings.USER_ACCESS_TOKEN_LIFETIME] + ['revoke_token']
    search_fields=("email","last_name","first_name")
    list_filter = (TokenStatusFilter,)

    fieldsets = (
        (None, {'fields': ('email','_token_enabled','_token','_token_created' ,'_token_expired')}),
        ('Personal info', {'fields': ('username','first_name', 'last_name')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', ),
        }),
        ('Important dates', {'fields': ('_last_login', '_date_joined')}),
    )

    object_change_url_name = None

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,))):
            return qs
        else:
            ids = [o.id for o in qs.only("id") if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(o.id,)))] 
            return qs.filter(id__in=ids)

    def _enable_token(self,request, queryset,enable):
        for user in queryset:
            try:
                try:
                    token = models.UserToken.objects.get(user=user)
                    if enable:
                        if token.enabled:
                            self.message_user(request, "{}: The access token was already enabled before".format(user.email))
                        else:
                            token.enabled = True
                            token.save(update_fields=["enabled"])
                            self.message_user(request, "{}: The access token is enabled.".format(user.email))
                    else:
                        if token.enabled:
                            token.enabled = False
                            token.save(update_fields=["enabled"])
                            self.message_user(request, "{}: The access token is disabled.".format(user.email))
                        else:
                            self.message_user(request, "{}: The access token was already disabled before".format(user.email))
                except ObjectDoesNotExist as ex:
                    if enable:
                        models.UserToken(user=user,enabled=True).save()
                        self.message_user(request, "{}: The access token is enabled".format(user.email))
                    else:
                        self.message_user(request, "{}: The access token was never enabled before.".format(user.email))
            except Exception as ex:
                logger.error("{}:Failed to {} the access token..{}".format(user.email,"enable" if enable else "disable",traceback.format_exc()))
                self.message_user(request, "{}:Failed to {} the access token..{}".format(user.email,"enable" if enable else "disable",str(ex)),level=messages.ERROR)

    def enable_token(self,request, queryset):
        self._enable_token(request,queryset,True)
    enable_token.short_description = 'Enable Access Token'

    def disable_token(self,request, queryset):
        self._enable_token(request,queryset,False)
    disable_token.short_description = 'Disable Access Token'

    def _create_token(self,request, queryset,token_lifetime=None):
        token = None
        enable_token = 0
        for user in queryset:
            try:
                enable_token = 0
                #enable the access token if not enabled before
                try:
                    token = models.UserToken.objects.get(user=user)
                    if not token.enabled:
                        token.enabled = True
                        enable_token = 1
                except ObjectDoesNotExist as ex:
                    token = models.UserToken(user=user,enabled=True)
                    enable_token = 2

                token.generate_token(token_lifetime=token_lifetime)
                if enable_token == 2:
                    token.save()
                    self.message_user(request, "{}: Succeed to enable and generate the access token".format(user.email))
                elif enable_token == 1:
                    token.save(update_fields=["enabled","token","created","expired"])
                    self.message_user(request, "{}: Succeed to enable and generate the access token".format(user.email))
                else:
                    token.save(update_fields=["token","created","expired"])
                    self.message_user(request, "{}: Succeed to generate the access token".format(user.email))

            except Exception as ex:
                logger.error("{}:Failed to generate access token..{}".format(user.email,traceback.format_exc()))
                self.message_user(request, "{}:Failed to generate access token..{}".format(user.email,str(ex)),level=messages.ERROR)

    def revoke_token(self,request, queryset):
        token = None
        for user in queryset:
            try:
                #enable the access token if not enabled before
                try:
                    token = models.UserToken.objects.get(user=user)
                    if not token.token:
                        self.message_user(request, "{}: Has no access token".format(user.email))
                    else:
                        token.token = None
                        token.created = None
                        token.expired = None
                        token.save(update_fields=["token","created","expired"])
                        self.message_user(request, "{}:Succeed to revoke the access token".format(user.email))

                except ObjectDoesNotExist as ex:
                    self.message_user(request, "{}: Has no access token".format(user.email))
            except Exception as ex:
                logger.error("{}:Failed to revoke access token..{}".format(user.email,traceback.format_exc()))
                self.message_user(request, "{}:Failed to revoke access token..{}".format(user.email,str(ex)),level=messages.ERROR)
    revoke_token.short_description = 'Revoke Access Token'

    def _token_enabled(self,obj):
        if not obj or not obj.token:
            return False
        else:
            return obj.token.enabled
    _token_enabled.boolean = True
    _token_enabled.short_description = "Token Enabled"

    def _token(self,obj):
        if not obj or not obj.token or not obj.token.token:
            return None
        else:
            return obj.token.token
    _token.short_description = "Token"

    def _token_short(self,obj):
        if not obj or not obj.token or not obj.token.token:
            return None
        else:
            return obj.token.token
    _token_short.short_description = "Token"

    def _token_created(self,obj):
        if not obj or not obj.token or not obj.token.token or not obj.token.created:
            return None
        else:
            return timezone.localtime(obj.token.created).strftime("%Y-%m-%d %H:%M:%S")
    _token_created.short_description = "Token Created At"

    def _token_expired(self,obj):
        if not obj or not obj.token or not obj.token.token:
            return None
        elif not obj.token.expired:
            return mark_safe("<A style='background-color:green;color:white;padding:0px 20px 0px 20px;'>2099-12-31</A>")
        else:
            t = obj.token.expired.strftime("%Y-%m-%d")
            status = obj.token.status
            if status < 0:
                return mark_safe("<A style='background-color:darkred;color:white;padding:0px 20px 0px 20px;'>{}</A>".format(t))
            elif status == models.UserToken.GOOD:
                return mark_safe("<A style='background-color:green;color:white;padding:0px 20px 0px 20px;'>{}</A>".format(t))
            else:
                return mark_safe("<A style='background-color:#ff9966;color:white;padding:0px 20px 0px 20px;'>{}</A>".format(t))
    _token_expired.short_description = "Token Expired At"


    def _token_is_expired(self,obj):
        if not obj or not obj.token or not obj.token.token:
            return None
        else:
            return mark_safe("<img src='{}'/>".format(static('admin/img/icon-%s.svg' % {True: 'yes', False: 'no'}[obj.token.is_expired])))
    _token_is_expired.short_description = "Token Expired"


    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

class UserAccessTokenAdmin(AccessTokenAdmin):
    object_change_url_name = 'admin:{}_{}_change'.format(NormalUserToken._meta.app_label,NormalUserToken._meta.model_name)

class SystemUserAccessTokenAdmin(AccessTokenAdmin):
    object_change_url_name = 'admin:{}_{}_change'.format(SystemUserToken._meta.app_label,SystemUserToken._meta.model_name)

for token_lifetime in settings.USER_ACCESS_TOKEN_LIFETIME:
    method_name = 'create_{}days_token'.format(token_lifetime) if token_lifetime > 0 else 'create_permenent_token'
    method_body = """
def {}(self,request,queryset):
    self._create_token(request,queryset,{})
""".format(method_name,token_lifetime)
    exec(method_body)
    setattr(UserAccessTokenAdmin,method_name,eval(method_name))
    setattr(SystemUserAccessTokenAdmin,method_name,eval(method_name))
    setattr(getattr(UserAccessTokenAdmin,method_name),"short_description",'Create {}days Token'.format(token_lifetime) if token_lifetime > 0 else 'Create Permanent Token')
    setattr(getattr(SystemUserAccessTokenAdmin,method_name),"short_description",'Create {}days Token'.format(token_lifetime) if token_lifetime > 0 else 'Create Permanent Token')

admin_site.register(SystemUserToken,SystemUserAccessTokenAdmin)
admin_site.register(NormalUserToken,UserAccessTokenAdmin)


class IdentityProviderAdmin(CacheableListTitleMixin,DatetimeMixin,djangoadmin.ModelAdmin):
    list_display = ('idp','name','userflow','logout_method','logout_url','_modified','_created')
    readonly_fields = ('idp','_modified','_created')
    form = forms.IdentityProviderForm
    fields = ('idp','name','userflow','logout_method','logout_url','_modified','_created')
    ordering = ('name','idp',)

    def has_add_permission(self, request, obj=None):
        return False

admin_site.register(models.IdentityProvider,IdentityProviderAdmin)


class CustomizableUserflowAdmin(CacheableListTitleMixin,DatetimeMixin,djangoadmin.ModelAdmin):
    list_display = ('domain','fixed','default','mfa_set',"mfa_reset",'password_reset','_modified','_created')
    readonly_fields = ('_modified','_created')
    form = forms.CustomizableUserflowForm
    fields = ('domain','fixed','default','mfa_set',"mfa_reset",'password_reset','extracss','page_layout',"verifyemail_from","verifyemail_subject","verifyemail_body","sortkey",'_modified','_created')
    ordering = (models.sortkey_c.asc(),)

    object_change_url_name = 'admin:{}_{}_change'.format(models.CustomizableUserflow._meta.app_label,models.CustomizableUserflow._meta.model_name)
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,))):
            return qs
        else:
            ids = [o.id for o in qs.only("id") if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(o.id,)))] 
            return models.CustomizableUserflow.objects.filter(id__in=ids)

    def has_add_permission(self, request, obj=None):
        return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,)))

    def has_delete_permission(self, request, obj=None):
        return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(-1,)))

admin_site.register(models.CustomizableUserflow,CustomizableUserflowAdmin)


class UserTOTPAdmin(DatetimeMixin,djangoadmin.ModelAdmin):
    list_display = ('name','email','issuer','timestep','algorithm','digits','prefix','last_verified_code','_last_verified','_created')
    readonly_fields = ('name','email','issuer','secret_key','timestep','algorithm','digits','prefix','last_verified_code','_last_verified','_created')
    fields = ('name','email','issuer','secret_key','timestep','algorithm','digits','prefix','last_verified_code','_last_verified','_created')
    ordering = ('name',)
    search_fields=("email",)

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
admin_site.register(models.UserTOTP,UserTOTPAdmin)
