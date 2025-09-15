from django.urls import path
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

from .. import views
from .base import basic_auth_wrapper

urlpatterns = [
    path('model/<slug:modelname>/changed',basic_auth_wrapper(views.config_changed),name="config_changed"),
    path('model/cachestatus',basic_auth_wrapper(views.model_cachestatus),name="model_cachestatus"),
    path('user/<int:userid>/changed',basic_auth_wrapper(views.user_changed),name="user_changed"),
    path('usertoken/<int:userid>/changed',basic_auth_wrapper(views.usertoken_changed),name="usertoken_changed"),
    path('users/changed',csrf_exempt(basic_auth_wrapper(views.users_changed)),name="users_changed"),
    path('usertokens/changed',csrf_exempt(basic_auth_wrapper(views.usertokens_changed)),name="usertokens_changed"),
    path('session/get',csrf_exempt(basic_auth_wrapper(views.get_remote_session)),name="get_session"),
    path('session/delete',csrf_exempt(basic_auth_wrapper(views.delete_remote_session)),name="delete_session"),
    path('trafficdata/save',basic_auth_wrapper(views.save_trafficdata),name="save_traffic_data"),
    path('status',basic_auth_wrapper(views.statusfactory("local")),name="cluster_status"),
    path('healthcheck',basic_auth_wrapper(views.healthcheckfactory("remote")),name="cluster_healthcheck")
]

if settings.AUTH2_MONITORING_DIR:
    urlpatterns.append(path('auth2status/<str:clusterid>', basic_auth_wrapper(views.auth2_status),name="auth2_status"))
    urlpatterns.append(path('auth2onlinestatus', basic_auth_wrapper(views.auth2_local_onlinestatus),name="auth2_onlinestatus"))
    urlpatterns.append(path('liveness/<str:clusterid>/<str:serviceid>/<str:monitordate>.html', basic_auth_wrapper(views.auth2_liveness),name="auth2_liveness"))

if settings.TRAFFICCONTROL_SUPPORTED:
    urlpatterns.append(path('tcontrol', basic_auth_wrapper(views.tcontrol),name="tcontrol"))


