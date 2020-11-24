from django.urls import include, path
from django.contrib import admin
from authome import views

urlpatterns = [
    path('sso/auth_logout', views.logout_view, name='logout'),
    path('sso/auth', views.auth, name='auth'),
    path('sso/auth_basic', views.auth_basic, name='auth_basic'),
    path('sso/profile', views.profile, name='profile'),
    path('sso/signup/check', views.check_signup, name='check_signup'),
    path('sso/', include('social_django.urls', namespace='social')),
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
]

