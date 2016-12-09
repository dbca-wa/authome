from django.conf.urls import url
from authome import views

urlpatterns = [
    url(r'^auth_logout', views.logout_view, name='logout'),
    url(r'^auth_redirect/', views.redirect, name='redirect'),
    url(r'^auth$', views.auth, name='auth'),
    url(r'^auth_dual$', views.auth_dual, name='auth_dual'),
    url(r'^auth_ip$', views.auth_ip, name='auth_ip'),
    url(r'^auth_get$', views.auth_get, name='auth_get'),
]
