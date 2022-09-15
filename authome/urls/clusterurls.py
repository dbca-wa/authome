from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from .. import views

urlpatterns = [
    path('model/<slug:modelname>/changed',views.config_changed,name="config_changed"),
    path('model/cachestatus',views.model_cachestatus,name="model_cachestatus"),
    path('user/<int:userid>/changed',views.user_changed,name="user_changed"),
    path('usertoken/<int:userid>/changed',views.usertoken_changed,name="usertoken_changed"),
    path('users/changed',csrf_exempt(views.users_changed),name="users_changed"),
    path('usertokens/changed',csrf_exempt(views.usertokens_changed),name="usertokens_changed"),
    path('session/get',csrf_exempt(views.get_remote_session),name="get_session"),
    path('session/delete',csrf_exempt(views.delete_remote_session),name="delete_session"),
    path('trafficdata/save',views.save_trafficdata,name="save_traffic_data"),
    path('status',views.statusfactory("local"),name="cluster_status"),
    path('healthcheck',views.healthcheckfactory("remote"),name="cluster_healthcheck")
]

