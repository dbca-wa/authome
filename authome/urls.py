from django.urls import include, path
from django.contrib import admin
from django.template.response import TemplateResponse
from django.conf import settings

from authome import views
from authome.cache import cache
import authome.patch

urlpatterns = [
    path('sso/auth_logout', views.logout_view, name='logout'),
    path('sso/auth', views.auth, name='auth'),
    path('sso/auth_optional', views.auth_optional, name='auth_optional'),
    path('sso/auth_basic', views.auth_basic, name='auth_basic'),
    path('sso/profile', views.profile, name='profile'),
    path('sso/signedout', views.signedout, name='signedout'),
    path('sso/forbidden', views.forbidden, name='forbidden'),
    path('sso/loginstatus', views.loginstatus, name='loginstatus'),
    path('sso/signup/check', views.check_signup, name='check_signup'),

    path('sso/<slug:template>.html', views.adb2c_view, name='adb2c_view'),

    path('sso/profile/edit', views.profile_edit,{"backend":"azuread-b2c-oauth2"},name='profile_edit'),
    path('sso/profile/edit/complete', views.profile_edit_complete,{"backend":"azuread-b2c-oauth2"},name='profile_edit_complete'),

    path('sso/email/signup', views.email_signup,{"backend":"azuread-b2c-oauth2"},name='email_signup'),
    path('sso/email/signup/complete', views.email_signup_complete,{"backend":"azuread-b2c-oauth2"},name='email_signup_complete'),

    path('sso/password/reset', views.password_reset,{"backend":"azuread-b2c-oauth2"},name='password_reset'),
    path('sso/password/reset/complete', views.password_reset_complete,{"backend":"azuread-b2c-oauth2"},name='password_reset_complete'),

    path('sso/', include('social_django.urls', namespace='social')),
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
]

if settings.DEBUG:
    import debug_toolbar
    urlpatterns.append(path('__debug__/', include(debug_toolbar.urls)))

def handler400(request,exception,**kwargs):
    code = exception.http_code if hasattr(exception,"http_code") else 400
    return TemplateResponse(request,"authome/error.html",context={"message":str(exception)},status=code)
  
#load cache
try:
    cache.refresh_authorization_cache(True)
    cache.refresh_idp_cache(True)
    cache.refresh_userflow_cache(True)
except:
    import traceback
    traceback.print_exc()
    pass
    
