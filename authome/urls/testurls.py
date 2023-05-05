from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from .. import views
from authome import performance
from .base import traffic_monitor

urlpatterns = [
    path('login_user',views.login_user,name="login_user"),
    #urlpatterns.append(path('__debug__/', include(debug_toolbar.urls)))
    path('sso/authperformance', performance.performancetester_wrapper(traffic_monitor("auth",views.auth)), name='authperformance'),
    path('sso/auth_basicperformance', performance.performancetester_wrapper(traffic_monitor("auth_basic",views.auth_basic)), name='auth_basicperformance'),
    path('echo',views.echo,name="echo"),
    path('echo/auth',views.echo,name="echo_auth"),
    path('echo/auth_basic',views.echo,name="echo_auth_basic"),
    path('echo/auth_optional',views.echo,name="echo_auth_optional"),
    path('session/get',views.get_session,name="get_session"),
    path('settings/get',views.get_settings,name="get_settings"),
    path('trafficdata/flush',views.flush_trafficdata,name="flush_trafficdata")
]

