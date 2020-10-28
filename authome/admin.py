import logging

from django.contrib import admin
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import User

from . import models
from . import forms

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

@admin.register(models.UserGroup)
class UserGroupAdmin(DatetimeMixin,admin.ModelAdmin):
    list_display = ('name','parent_group','users','excluded_users','_modified','_created')
    readonly_fields = ('_modified',)
    fields = ('name','parent_group','users','excluded_users','_modified')
    ordering = ('parent_group','name',)
    form = forms.UserGroupForm

@admin.register(models.UserGroupRequests)
class UserGroupRequestsAdmin(DatetimeMixin,admin.ModelAdmin):
    list_display = ('usergroup','domain','paths','excluded_paths','_modified','_created')
    readonly_fields = ('_modified',)
    fields = ('usergroup','domain','paths','excluded_paths','_modified')
    ordering = ('usergroup','sortkey',)
    form = forms.UserGroupRequestsForm

@admin.register(models.UserRequests)
class UserRequestsAdmin(DatetimeMixin,admin.ModelAdmin):
    list_display = ('user','domain','paths','excluded_paths','_modified','_created')
    readonly_fields = ('_modified',)
    fields = ('user','domain','paths','excluded_paths','_modified')
    ordering = ('user','sortkey',)
    form = forms.UserGroupRequestsForm

class UserAccessToken(User):
    class Meta:
            proxy = True

@admin.register(UserAccessToken)
class UserTokenAdmin(admin.ModelAdmin):
    list_display = ('email','last_name','first_name','is_staff','is_superuser','is_active','_token_enabled','_token_short','_token_created','_token_expired','_token_is_expired')
    readonly_fields = ('email','last_name','first_name','is_staff','is_superuser','is_active','_token_enabled','_token','_token_created','_token_expired','_token_is_expired')
    fields = list_display
    ordering = ('email',)

    def _token_enabled(self,obj):
        if not obj or not obj.token:
            return False
        else:
            return obj.token.enabled
    _token_enabled.short_description = "Token Enabled"

    def _token(self,obj):
        if not obj or not obj.token or not obj.token.enabled or not obj.token.token:
            return ""
        else:
            return obj.token.token
    _token.short_description = "Token"

    def _token_short(self,obj):
        if not obj or not obj.token or not obj.token.enabled or not obj.token.token:
            return ""
        else:
            return "{}...".format(obj.token.token[:16])
    _token_short.short_description = "Token"

    def _token_created(self,obj):
        if not obj or not obj.token or not obj.token.enabled or not obj.token.token or not obj.token.created:
            return ""
        else:
            return timezone.localtime(obj.token.created).strftime("%Y-%m-%d %H:%M:%S")
    _token_created.short_description = "Token Created"

    def _token_expired(self,obj):
        if not obj or not obj.token or not obj.token.enabled or not obj.token.token or not obj.token.expired:
            return ""
        else:
            return obj.token.expired.strftime("%Y-%m-%d")
    _token_expired.short_description = "Token Expired"


    def _token_is_expired(self,obj):
        if not obj or not obj.token  or not obj.token.enabled or not obj.token.token:
            return ""
        else:
            return obj.token.is_expired
    _token_is_expired.short_description = "Token Expired"


    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False



