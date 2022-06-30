from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from .. import views

urlpatterns = [
    path('model/<slug:modelname>/changed',views.config_changed,name="config_changed"),
    path('user/<int:userid>/changed',views.user_changed,name="user_changed"),
    path('usertoken/<int:userid>/changed',views.usertoken_changed,name="usertoken_changed"),
    path('users/changed',csrf_exempt(views.users_changed),name="users_changed"),
    path('usertokens/changed',csrf_exempt(views.usertokens_changed),name="usertokens_changed"),
    path('session/get',csrf_exempt(views.get_remote_session),name="get_session"),
    path('trafficdata',views.trafficmonitorfactory("local"),name="get_traffic_data")
]

