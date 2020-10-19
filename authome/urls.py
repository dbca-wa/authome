from django.urls import include, path
from authome import views

urlpatterns = [
    path('sso/auth_logout', views.logout_view, name='logout'),
    path('sso/auth', views.auth, name='auth'),
    path('sso/auth_dual', views.auth_dual, name='auth_dual'),
    path('sso/auth_ip', views.auth_ip, name='auth_ip'),
    path('sso/auth_get', views.auth_get, name='auth_get'),
    path('ssouser/<slug:user_template>', views.user_view, name='user_view'),
    path('sso/', include('social_django.urls', namespace='social')),
    path('', views.home, name='home'),
]

