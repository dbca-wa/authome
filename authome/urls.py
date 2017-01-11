from django.conf.urls import include, url
from authome import views

urlpatterns = [
    url(r'^sso/auth_logout', views.logout_view, name='logout'),
    url(r'^sso/auth$', views.auth, name='auth'),
    url(r'^sso/auth_dual$', views.auth_dual, name='auth_dual'),
    url(r'^sso/auth_ip$', views.auth_ip, name='auth_ip'),
    url(r'^sso/auth_get$', views.auth_get, name='auth_get'),
    url(r'^sso/', include('social_django.urls', namespace='social')),
    url(r'', views.home, name='home'),
]
