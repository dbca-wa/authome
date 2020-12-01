from django.urls import include, path
from django.contrib import admin
from authome import views
from authome.cache import cache

urlpatterns = [
    path('sso/auth_logout', views.logout_view, name='logout'),
    path('sso/auth', views.auth, name='auth'),
    path('sso/auth_basic', views.auth_basic, name='auth_basic'),
    path('sso/profile', views.profile, name='profile'),
    path('sso/signedout', views.signedout, name='signedout'),
    path('sso/signup/check', views.check_signup, name='check_signup'),
    path('sso/', include('social_django.urls', namespace='social')),
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
]
  
#load cache
try:
    cache.refresh_authorization_cache(True)
    cache.refresh_idp_cache(True)
except:
    pass
    
