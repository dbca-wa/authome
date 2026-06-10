from django.urls import path,re_path
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

from .. import views
from authome import performance
from .base import traffic_monitor

urlpatterns = [
    path('login_user',views.login_user,name="login_user"),
    #urlpatterns.append(path('__debug__/', include(debug_toolbar.urls)))
    path('sso/authperformance', performance.performancetester_wrapper(traffic_monitor("auth",views.auth)), name='authperformance'),
    path('sso/auth_basicperformance', performance.performancetester_wrapper(traffic_monitor("auth_basic",views.auth_basic)), name='auth_basicperformance'),
    re_path(r"^echo/?$", views.echo,name="echo"),
    path('echo/auth',views.echo,name="echo_auth"),
    path('echo/auth_basic',views.echo,name="echo_auth_basic"),
    path('echo/auth_basic_optional',views.echo,name="echo_auth_basic_optional"),
    path('echo/auth_optional',views.echo,name="echo_auth_optional"),
    path('model/<slug:name>/update',csrf_exempt(views.update_model_4_test),name="update_model_4_test"),
    path('model/<slug:name>/delete',csrf_exempt(views.del_model_4_test),name="del_model_4_test"),
    path('model/<slug:name>/search',csrf_exempt(views.search_model_4_test),name="search_model_4_test"),
    path('model/<slug:name>/refreshcache',csrf_exempt(views.refresh_modelcache_4_test),name="refresh_modelcache_4_test"),
    path('session/get',views.get_session,name="get_session"),
    path('settings/get',views.get_settings,name="get_settings"),
    path('trafficdata/flush',views.flush_trafficdata,name="flush_trafficdata"),
    path('trafficdata/save',views.save_trafficdata_to_db,name="save_trafficdata"),
    path('deleteofflineclusters',views.delete_offline_clusters,name="delete_offline_clusters")
]
