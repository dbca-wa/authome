import logging
import traceback

from django.urls import include, path
from django.contrib import admin
from django.conf import settings
from django.template.response import TemplateResponse
from django.views.generic.base import RedirectView
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

from . import views
from .cache import cache
from . import utils

import authome.patch

logger = logging.getLogger(__name__)

def traffic_monitor(name,func):
    def _monitor(request):
        start = timezone.now()
        res = None
        try:
           res = func(request)
           return res
        finally:
            try:
                cache.log_request(name,utils.get_host(request),start,res.status_code if res else 500)
            except:
                logger.error("Failed to log the request.{}".format(traceback.format_exc()))
        
        
    return _monitor if settings.TRAFFIC_MONITOR_LEVEL > 0 else func

urlpatterns = [
    path('sso/auth_logout', views.logout_view, name='logout'),
    path('sso/auth_local', views.auth_local, name='auth_local'),
    path('sso/auth', traffic_monitor("auth",views.auth), name='auth'),
    path('sso/auth_optional', traffic_monitor("auth_optional",views.auth_optional), name='auth_optional'),
    path('sso/auth_basic', traffic_monitor("auth_basic",views.auth_basic), name='auth_basic'),
    path('sso/login_domain', csrf_exempt(views.login_domain), name='login_domain'),
    path('sso/profile', views.profile, name='profile'),
    path('sso/signedout', views.signedout, name='signedout'),
    path('sso/forbidden', views.forbidden, name='forbidden'),
    path('sso/loginstatus', views.loginstatus, name='loginstatus'),

    path('sso/verifycode', views.verify_code_via_email, name='verify_code'),

    path('sso/<slug:template>.html', views.adb2c_view, name='adb2c_view'),

    #path('sso/profile/edit', views.profile_edit,{"backend":"azuread-b2c-oauth2"},name='profile_edit'),
    #path('sso/profile/edit/complete', views.profile_edit_complete,{"backend":"azuread-b2c-oauth2"},name='profile_edit_complete'),
    path('sso/profile/edit', views.profile_edit,name='profile_edit'),

    path('sso/password/reset', views.password_reset,{"backend":"azuread-b2c-oauth2"},name='password_reset'),
    path('sso/password/reset/complete', views.password_reset_complete,{"backend":"azuread-b2c-oauth2"},name='password_reset_complete'),

    path('sso/mfa/set', views.mfa_set,{"backend":"azuread-b2c-oauth2"},name='mfa_set'),
    path('sso/mfa/set/complete', views.mfa_set_complete,{"backend":"azuread-b2c-oauth2"},name='mfa_set_complete'),

    path('sso/mfa/reset', views.mfa_reset,{"backend":"azuread-b2c-oauth2"},name='mfa_reset'),
    path('sso/mfa/reset/complete', views.mfa_reset_complete,{"backend":"azuread-b2c-oauth2"},name='mfa_reset_complete'),

    path('sso/totp/generate',views.totp_generate,name="totp_generate"),
    path('sso/totp/verify',views.totp_verify,name="totp_verify"),

    path('sso/setting',views.user_setting,name="user_setting"),

    path('sso/checkauthorization',csrf_exempt(views.checkauthorization),name="checkauthorization"),

    path('healthcheck',views.healthcheck,name="healthcheck"),
    path('trafficmonitor',views.trafficmonitor,name="trafficmonitor"),
    path('status',views.status,name="status"),

    path('sso/', include('social_django.urls', namespace='social')),
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),

    path("favicon.ico",RedirectView.as_view(url="{}images/favicon.ico".format(settings.STATIC_URL)))
]
if settings.DEBUG:
    #import debug_toolbar
    from authome import performance
    #urlpatterns.append(path('__debug__/', include(debug_toolbar.urls)))
    urlpatterns.append(path('sso/authperformance', performance.performancetester_wrapper(views.auth), name='authperformance'))
    urlpatterns.append(path('sso/auth_basicperformance', performance.performancetester_wrapper(views.auth_basic), name='auth_basicperformance'))
    urlpatterns.append(path('echo',views.echo,name="echo"))
    urlpatterns.append(path('echo/auth',views.echo,name="echo_auth"))
    urlpatterns.append(path('echo/auth_basic',views.echo,name="echo_auth_basic"))
    urlpatterns.append(path('echo/auth_optional',views.echo,name="echo_auth_optional"))

handler400 = views.handler400

#load cache
try:
    cache.refresh_authorization_cache(True)
except:
    if not settings.IGNORE_LOADING_ERROR:
        raise Exception("Failed to load UserGroup and UserGroupAuthorization cache during server startingFailed to load UserGroup and UserGroupAuthorization cache during server starting.{}".format(traceback.format_exc()))
    
try:
    cache.refresh_idp_cache(True)
except:
    if not settings.IGNORE_LOADING_ERROR:
        raise Exception("Failed to load IdentityProvider cache during server startingFailed to load UserGroup and UserGroupAuthorization cache during server starting.{}".format(traceback.format_exc()))
    
try:
    cache.refresh_userflow_cache(True)
except:
    if not settings.IGNORE_LOADING_ERROR:
        raise Exception("Failed to load CustomizableUserflow cache during server startingFailed to load UserGroup and UserGroupAuthorization cache during server starting.{}".format(traceback.format_exc()))
    
