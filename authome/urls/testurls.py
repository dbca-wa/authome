from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from .. import views

urlpatterns = [
    path('login_user',views.login_user,name="login_user"),
]

