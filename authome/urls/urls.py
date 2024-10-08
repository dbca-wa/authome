import logging

from django.urls import include, path
from django.conf import settings
from django.views.generic.base import RedirectView
from django.views.decorators.csrf import csrf_exempt

from .. import views
from ..cache import cache
from ..admin import admin_site
from .base import traffic_monitor

logger = logging.getLogger(__name__)

admin_urls = admin_site.urls

if settings.AUTH2_MONITORING_DIR:
    if settings.AUTH2_CLUSTER_ENABLED:
        admin_urls[0].insert(0,path('auth2status/<str:clusterid>', views.auth2_status,name="auth2_status"))
        admin_urls[0].insert(1,path('liveness/<str:clusterid>/<str:serviceid>/<str:monitordate>.html', views.auth2_liveness,name="auth2_liveness"))
    else:
        admin_urls[0].insert(0,path('healthcheck', views.auth2_healthcheck,name="auth2_healthcheck"))
        admin_urls[0].insert(1,path('liveness/<str:serviceid>/<str:monitordate>.html', views.auth2_liveness,name="auth2_liveness"))

admin_urls[0].insert(0,path('authome/tools/apple/secretkey/renew', views.renew_apple_secretkey,name="renew_apple_secretkey"))

urlpatterns = [
    path('sso/auth_logout', views.logout_view, name='logout'),
    path('sso/auth_local', views.auth_local, name='auth_local'),
    path('sso/auth', traffic_monitor("auth",views.auth), name='auth'),
    path('sso/auth_optional', traffic_monitor("auth_optional",views.auth_optional), name='auth_optional'),
    path('sso/auth_basic', traffic_monitor("auth_basic",views.auth_basic), name='auth_basic'),
    path('sso/auth_basic_optional', traffic_monitor("auth_basic_optional",views.auth_basic_optional), name='auth_basic_optional'),
    path('sso/login_domain', csrf_exempt(views.login_domain), name='login_domain'),
    path('sso/profile', views.profile, name='profile'),
    path('sso/signout_socialmedia', views.signout_socialmedia, name='signout_socialmedia'),
    path('sso/signedout', views.signedout, name='signedout'),
    path('sso/forbidden', views.forbidden, name='forbidden'),
    path('sso/loginstatus', views.loginstatus, name='loginstatus'),

    path('sso/verifycode', views.verify_code_via_email, name='verify_code'),

    path('sso/<slug:template>.html', views.adb2c_view, name='adb2c_view'),

    #path('sso/profile/edit', views.profile_edit,{"backend":"azuread-b2c-oauth2"},name='profile_edit'),
    #path('sso/profile/edit/complete', views.profile_edit_complete,{"backend":"azuread-b2c-oauth2"},name='profile_edit_complete'),

    path('sso/password/reset', views.password_reset,{"backend":"azuread-b2c-oauth2"},name='password_reset'),
    path('sso/password/reset/complete', views.password_reset_complete,{"backend":"azuread-b2c-oauth2"},name='password_reset_complete'),

    path('sso/mfa/set', views.mfa_set,{"backend":"azuread-b2c-oauth2"},name='mfa_set'),
    path('sso/mfa/set/complete', views.mfa_set_complete,{"backend":"azuread-b2c-oauth2"},name='mfa_set_complete'),

    path('sso/mfa/reset', views.mfa_reset,{"backend":"azuread-b2c-oauth2"},name='mfa_reset'),
    path('sso/mfa/reset/complete', views.mfa_reset_complete,{"backend":"azuread-b2c-oauth2"},name='mfa_reset_complete'),

    path('sso/totp/generate',views.totp_generate,name="totp_generate"),
    path('sso/totp/verify',views.totp_verify,name="totp_verify"),

    path('sso/setting',views.selfservice.user_setting,name="user_setting"),

    path('sso/checkauthorization',csrf_exempt(views.checkauthorization),name="checkauthorization"),

    path('healthcheck',views.healthcheckfactory(),name="healthcheck"),
    path('status',views.statusfactory(),name="status"),
    path('ping',views.ping,name="ping"),

    path('sso/', include('social_django.urls', namespace='social')),
    path('admin/', admin_urls),
    path('', views.home, name='home'),

    path("favicon.ico",RedirectView.as_view(url="{}images/favicon.ico".format(settings.STATIC_URL)))
]
if settings.DEBUG:
    #import debug_toolbar
    pass

handler400 = views.handler400
