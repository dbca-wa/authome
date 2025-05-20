import logging
import traceback

from django.http import HttpResponseRedirect
from django.contrib import admin as djangoadmin
from django.utils import timezone
from django.conf import settings
from django.contrib import messages, auth
from django.core.exceptions import ObjectDoesNotExist
from django.utils.html import mark_safe
from django.db.models import Q
from django.contrib.admin.views.main import ChangeList
from django.urls import reverse
from django.template.response import TemplateResponse

from .. import models
from .. import forms

logger = logging.getLogger(__name__)

class CatchModelExceptionMixin(object):
    def change_view(self,request,*args,**kwargs):
        try:
            return super().change_view(request,*args,**kwargs)
        except Exception as ex:
            self.message_user(request, str(ex),level=messages.ERROR)
            return HttpResponseRedirect(request.get_full_path())

class ExtraToolsChangeList(ChangeList):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extra_tools = self.model_admin.extra_tools

class ExtraToolsMixin(object):
    extra_tools = None
    def get_changelist(self, request, **kwargs):
        """
        Return the ChangeList class for use on the changelist page.
        """
        return ExtraToolsChangeList

class PermissionCheckMixin(object):
    object_change_url_name = None
    object_delete_url_name = None
    model = None
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(0,))):
            return qs
        else:
            qs = qs.only("id")
            ids = [o.id for o in qs if models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(o.id,)))]
            return self.model.objects.filter(id__in=ids)

    def has_add_permission(self, request, obj=None):
        if obj:
            return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(obj.id,)))
        else:
            return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(0,)))

    def has_delete_permission(self, request, obj=None):
        if obj:
            return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_delete_url_name, args=(obj.id,)))
        else:
            return models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_delete_url_name, args=(0,)))


class CacheableChangeList(ChangeList):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.extra_tools = self.model_admin.extra_tools
        logger.debug("Refresh the model({}) data if required".format(self.model))
        self.model.refresh_cache_if_required()

        if self.model.is_outdated():
            self.title = "{}({}Cache is outdated, latest refresh time is {}, next refresh time is {})".format(
                self.title,
                "{} : ".format(settings.AUTH2_CLUSTERID) if settings.AUTH2_CLUSTER_ENABLED else "",
                timezone.localtime(self.model.get_cachetime()).strftime("%Y-%m-%d %H:%M:%S") if self.model.get_cachetime() else "None",
                timezone.localtime(self.model.get_next_refreshtime()).strftime("%Y-%m-%d %H:%M:%S") if self.model.get_next_refreshtime() else "None"
            )
        else:
            self.title = "{}({}Cache is up-to-date, latest refresh time is {}, next refresh time is {})".format(
                self.title,
                "{} : ".format(settings.AUTH2_CLUSTERID) if settings.AUTH2_CLUSTER_ENABLED else "",
                timezone.localtime(self.model.get_cachetime()).strftime("%Y-%m-%d %H:%M:%S") if self.model.get_cachetime() else "None",
                timezone.localtime(self.model.get_next_refreshtime()).strftime("%Y-%m-%d %H:%M:%S") if self.model.get_next_refreshtime() else "None"
            )


class CacheableListTitleMixin(object):
    extra_tools = None
    def get_changelist(self, request, **kwargs):
        """
        Return the ChangeList class for use on the changelist page.
        """
        return CacheableChangeList

class DatetimeMixin(object):
    def _batchid(self,obj):
        if not obj or not obj.batchid :
            return ""
        else:
            return timezone.localtime(obj.batchid).strftime("%Y-%m-%d %H:%M:%S")
    _batchid.short_description = "Batchid"

    def _secretkey_expireat(self,obj):
        if not obj or not obj.secretkey_expireat :
            return ""
        else:
            return timezone.localtime(obj.secretkey_expireat).strftime("%Y-%m-%d %H:%M:%S")
    _secretkey_expireat.short_description = "Secret Key Expire At"


    def _start_time(self,obj):
        if not obj or not obj.start_time :
            return ""
        else:
            return timezone.localtime(obj.start_time).strftime("%Y-%m-%d %H:%M:%S")
    _start_time.short_description = "Start Time"

    def _end_time(self,obj):
        if not obj or not obj.end_time :
            return ""
        else:
            return timezone.localtime(obj.end_time).strftime("%Y-%m-%d %H:%M:%S")
    _end_time.short_description = "End Time"

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

    def _registered(self,obj):
        if not obj or not obj.registered :
            return ""
        else:
            return timezone.localtime(obj.registered).strftime("%Y-%m-%d %H:%M:%S")
    _registered.short_description = "Registered"

    def _last_heartbeat(self,obj):
        if not obj or not obj.last_heartbeat :
            return ""
        else:
            return timezone.localtime(obj.last_heartbeat).strftime("%Y-%m-%d %H:%M:%S")
    _last_heartbeat.short_description = "Last Heartbeat"

    def _usergroup_lastrefreshed(self,obj):
        if not obj or not obj.usergroup_lastrefreshed :
            return ""
        else:
            return timezone.localtime(obj.usergroup_lastrefreshed).strftime("%Y-%m-%d %H:%M:%S")
    _usergroup_lastrefreshed.short_description = "Usergroup Last Refreshed"

    def _usergroupauthorization_lastrefreshed(self,obj):
        if not obj or not obj.usergroupauthorization_lastrefreshed :
            return ""
        else:
            return timezone.localtime(obj.usergroupauthorization_lastrefreshed).strftime("%Y-%m-%d %H:%M:%S")
    _usergroupauthorization_lastrefreshed.short_description = "Usergroup Authorization Last Refreshed"

    def _userflow_lastrefreshed(self,obj):
        if not obj or not obj.userflow_lastrefreshed :
            return ""
        else:
            return timezone.localtime(obj.userflow_lastrefreshed).strftime("%Y-%m-%d %H:%M:%S")
    _userflow_lastrefreshed.short_description = "Userflow Last Refreshed"

    def _idp_lastrefreshed(self,obj):
        if not obj or not obj.idp_lastrefreshed :
            return ""
        else:
            return timezone.localtime(obj.idp_lastrefreshed).strftime("%Y-%m-%d %H:%M:%S")
    _idp_lastrefreshed.short_description = "IDP Last Refreshed"


class RequestMixin(object):
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        self._request = request
        return qs


class UserGroupsMixin(RequestMixin):
    group_change_url_name = 'admin:{}_{}_change'.format(models.UserGroup._meta.app_label,models.UserGroup._meta.model_name)

    def _usergroups(self,obj):
        if not obj :
            return ""
        else:
            usergroups,usergroupnames,grouppks = models.UserGroup.find_groups(obj.email,cacheable=False)
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

    def _session_timeout(self,obj):
        if not obj :
            return "-"
        else:
            usergroups = models.UserGroup.find_groups(obj.email,cacheable=False)[0]
            return models.UserGroup.get_session_timeout(usergroups) or "-"
    _session_timeout.short_description = "Session Timeout"

        

    def _usergroupnames(self,obj):
        if not obj :
            return ""
        else:
            return models.UserGroup.find_groups(obj.email,cacheable=False)[1]
    _usergroupnames.short_description = "User Group Names"

class DbcaAccountMixin(RequestMixin):
    def _is_staff(self,obj):
        if not obj :
            return False
        else:
            return obj.is_staff
    _is_staff.boolean = True
    _is_staff.short_description = "DBCA Account?"


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
        verbose_name_plural="{}Users".format(" " * 16)

class DeleteMixin(object):
    def delete_model(self, request, obj):
        try:
            super().delete_model(request,obj)
        except Exception as ex:
            self.message_user(request, "Failed to delete {}({}).{}".format(obj.__class__.__name__,obj,ex),level=messages.ERROR)

    def delete_queryset(self, request, queryset):
        for o in queryset:
            self.delete_model(request,o)

class UserAdmin(UserAuthorizationCheckMixin,UserGroupsMixin,DatetimeMixin,CatchModelExceptionMixin,auth.admin.UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name','is_active', 'is_staff','_session_timeout','last_idp','_last_login')
    list_filter = ( 'is_superuser',)
    readonly_fields = ("_last_login","_date_joined","username","first_name","last_name","is_staff","is_superuser","_email","_usergroups","_session_timeout","last_idp","_modified")
    fieldsets = (
        (None, {'fields': ('_email', )}),
        ('Personal info', {'fields': ('username','first_name', 'last_name',"_session_timeout")}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser',"_usergroups" ),
        }),
        ('Important dates', {'fields': ('last_idp','_last_login', '_date_joined','_modified')}),
    )

    change_form_template = 'admin/change_form.html'
    form = forms.UserEditForm
    actions = ["check_authorization"]

    def _email(self,obj):
        if not obj :
            return ""
        else:
            return obj.email
    _email.short_description = "Email"

    def has_add_permission(self, request, obj=None):
        return False

class SystemUser(models.User):
    objects = models.SystemUserManager()
    class Meta:
        proxy = True
        verbose_name="System User"
        verbose_name_plural="{}System Users".format(" " * 14)


class SystemUserAdmin(PermissionCheckMixin,DbcaAccountMixin,UserGroupsMixin,DatetimeMixin,CatchModelExceptionMixin,auth.admin.UserAdmin):
    list_display = ('username', 'email', 'is_active', '_usergroups',"_is_staff",'_date_joined')
    list_filter = ("is_active",)
    add_form_template = 'admin/change_form.html'
    change_form_template = 'admin/change_form.html'
    add_form = forms.SystemUserCreateForm
    form = forms.SystemUserEditForm
    readonly_fields = ("_date_joined","username","_email","_is_staff","_usergroups")
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ("email",)
        }),
    )
    fieldsets = (
        (None, {'fields': ('_email',"comments")}),
        ('Personal info', {'fields': ('username',)}),
        ('Permissions', {
            'fields': ('is_active', "_is_staff","_usergroups"),
        }),
        ('Important dates', {'fields': ('_date_joined',)}),
    )

    model = SystemUser
    object_change_url_name = 'admin:{}_{}_change'.format(SystemUser._meta.app_label,SystemUser._meta.model_name)
    object_delete_url_name = 'admin:{}_{}_delete'.format(SystemUser._meta.app_label,SystemUser._meta.model_name)

    def _email(self,obj):
        if not obj :
            return ""
        else:
            return obj.email
    _email.short_description = "Email"

class UserGroupAdmin(PermissionCheckMixin,CacheableListTitleMixin,DatetimeMixin,CatchModelExceptionMixin,djangoadmin.ModelAdmin):
    list_display = ('name','groupid','parent_group','users','excluded_users','identity_provider','_session_timeout','_modified','_created')
    fields = ('name','groupid','parent_group','users','excluded_users','identity_provider','session_timeout','_modified')
    ordering = ('parent_group','name',)
    search_fields=("name",)
    list_filter = ['parent_group']
    form = forms.UserGroupForm

    model = models.UserGroup
    object_change_url_name = 'admin:{}_{}_change'.format(models.UserGroup._meta.app_label,models.UserGroup._meta.model_name)
    object_delete_url_name = 'admin:{}_{}_delete'.format(models.UserGroup._meta.app_label,models.UserGroup._meta.model_name)

    def get_readonly_fields(self, request, obj=None):
        if not obj or not obj.id:
            return ('_modified',)
        elif models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(0,))):
            # can modify any objects
            return ('_modified',)
        else:
            return ('_modified','name','groupid','parent_group')

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

class UserGroupAuthorizationAdmin(PermissionCheckMixin,CacheableListTitleMixin,DatetimeMixin,CatchModelExceptionMixin,djangoadmin.ModelAdmin):
    list_display = ('usergroup','domain','paths','excluded_paths','_modified','_created')
    readonly_fields = ('_modified',)
    fields = ('usergroup','domain','paths','excluded_paths','_modified')
    ordering = ('usergroup',models.sortkey_c.asc())
    search_fields=("domain",)
    list_filter = ['usergroup']
    form = forms.UserGroupAuthorizationForm

    model = models.UserGroupAuthorization
    object_change_url_name = 'admin:{}_{}_change'.format(models.UserGroupAuthorization._meta.app_label,models.UserGroupAuthorization._meta.model_name)
    object_delete_url_name = 'admin:{}_{}_delete'.format(models.UserGroupAuthorization._meta.app_label,models.UserGroupAuthorization._meta.model_name)

    def get_readonly_fields(self, request, obj=None):
        if not obj or not obj.id:
            return ('_modified',)
        elif models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(0,))):
            # can modify any objects
            return ('_modified','usergroup')
        else:
            return ('_modified','usergroup','domain')


class UserAuthorizationAdmin(CacheableListTitleMixin,DatetimeMixin,CatchModelExceptionMixin,djangoadmin.ModelAdmin):
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
        verbose_name_plural="{}System User Tokens".format(" " * 13)

class NormalUserToken(models.User):
    objects = models.NormalUserManager()
    class Meta:
        proxy = True
        verbose_name="System User"
        verbose_name_plural="{}User Tokens".format(" " * 15)


class AccessTokenAdmin(DatetimeMixin,CatchModelExceptionMixin,auth.admin.UserAdmin):
    ordering = ('email',)
    change_form_template = 'admin/change_form.html'
    actions = ['enable_token','disable_token'] + ['create_{}days_token'.format(o) if o > 0 else 'create_permenent_token' for o in settings.USER_ACCESS_TOKEN_LIFETIME] + ['revoke_token']
    search_fields=("email","last_name","first_name")
    list_filter = (TokenStatusFilter,)

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


    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

class UserAccessTokenAdmin(AccessTokenAdmin):
    object_change_url_name = 'admin:{}_{}_change'.format(NormalUserToken._meta.app_label,NormalUserToken._meta.model_name)
    list_display = ('email','last_name','first_name','_token_enabled','_token_short','_token_created','_token_expired')
    readonly_fields = ('email','username','last_name','first_name','_token_enabled','_token','_token_created','_token_expired',"is_active","is_staff","is_superuser","_last_login","_date_joined")
    fieldsets = (
        (None, {'fields': ('email','_token_enabled','_token','_token_created' ,'_token_expired')}),
        ('Personal info', {'fields': ('username','first_name', 'last_name')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', ),
        }),
        ('Important dates', {'fields': ('_last_login', '_date_joined')}),
    )


class SystemUserAccessTokenAdmin(PermissionCheckMixin,DbcaAccountMixin,AccessTokenAdmin):
    model = SystemUserToken
    object_change_url_name = 'admin:{}_{}_change'.format(SystemUserToken._meta.app_label,SystemUserToken._meta.model_name)
    object_delete_url_name = 'admin:{}_{}_delete'.format(SystemUserToken._meta.app_label,SystemUserToken._meta.model_name)

    list_display = ('email','_token_enabled','_token_short','_token_created','_token_expired')
    readonly_fields = ('email','_token_enabled','_token','_token_created','_token_expired',"username","comments","is_active","_is_staff","_date_joined")
    fieldsets = (
        (None, {'fields': ('email','_token_enabled','_token','_token_created' ,'_token_expired')}),
        ('Personal info', {'fields': ('username','comments')}),
        ('Permissions', {
            'fields': ('is_active', '_is_staff' ),
        }),
        ('Important dates', {'fields': ('_date_joined',)}),
    )

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


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

class IdentityProviderAdmin(CacheableListTitleMixin,DatetimeMixin,CatchModelExceptionMixin,djangoadmin.ModelAdmin):
    list_display = ('idp','name','userflow','logout_method','logout_url','secretkey_expiretime','_modified','_created')
    readonly_fields = ('idp','_modified','_created')
    form = forms.IdentityProviderForm
    fields = ('idp','name','userflow','logout_method','logout_url','secretkey_expireat','_modified','_created')
    ordering = ('name','idp',)

    def has_add_permission(self, request, obj=None):
        return False


class CustomizableUserflowAdmin(PermissionCheckMixin,CacheableListTitleMixin,DatetimeMixin,CatchModelExceptionMixin,djangoadmin.ModelAdmin):
    list_display = ('domain','fixed','default','mfa_set',"mfa_reset",'password_reset','_modified','_created')
    readonly_fields = ('_modified','_created')
    form = forms.CustomizableUserflowForm
    fields = ('domain','fixed','default','mfa_set',"mfa_reset",'password_reset','extracss','page_layout',"verifyemail_from","verifyemail_subject","verifyemail_body","signedout_url","relogin_url","signout_body","sortkey",'_modified','_created')
    ordering = (models.sortkey_c.asc(),)
    search_fields=("domain",)

    model = models.CustomizableUserflow
    object_change_url_name = 'admin:{}_{}_change'.format(models.CustomizableUserflow._meta.app_label,models.CustomizableUserflow._meta.model_name)
    object_delete_url_name = 'admin:{}_{}_delete'.format(models.CustomizableUserflow._meta.app_label,models.CustomizableUserflow._meta.model_name)

    def get_readonly_fields(self, request, obj=None):
        if not obj or not obj.id:
            return ('_modified','_created')
        elif models.can_access(request.user.email,settings.AUTH2_DOMAIN,reverse(self.object_change_url_name, args=(0,))):
            # can modify any objects
            return ('_modified','_created')
        else:
            return ('_modified','_created',"domain")


class UserTOTPAdmin(DatetimeMixin,CatchModelExceptionMixin,djangoadmin.ModelAdmin):
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

