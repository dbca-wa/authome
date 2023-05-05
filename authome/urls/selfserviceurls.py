from django.urls import path
from django.views.decorators.csrf import csrf_exempt

from ..views import selfservice

urlpatterns = [
    path('profile/edit', selfservice.profile_edit,name='profile_edit'),
    path('token/enable',selfservice.enable_token,name="enable_token"),
    path('token/disable',selfservice.disable_token,name="disable_token"),
    path('token/revoke',selfservice.revoke_token,name="revoke_token"),
    path('token/create/<int:index>',selfservice.create_token,name="create_token"),
]

