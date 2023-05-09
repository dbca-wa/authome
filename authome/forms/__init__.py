from django.conf import settings

from .forms import *

if settings.AUTH2_CLUSTER_ENABLED:
    #from .clusterforms import UserEditForm
    pass
