from django.urls import include, path
from django.contrib import admin
from authome import views

urlpatterns = [
    path('sso/auth_logout', views.logout_view, name='logout'),
    path('sso/auth', views.auth, name='auth'),
    path('sso/auth_basic', views.auth_basic, name='auth_basic'),
    path('sso/auth_token', views.auth_token, name='auth_token'),
    path('ssoauth/<slug:user_template>', views.auth_view, name='auth_view'),
    path('sso/', include('social_django.urls', namespace='social')),
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
]

