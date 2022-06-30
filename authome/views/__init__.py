from django.conf import settings

from .views import *
from .monitorviews import *
from ..cache import cache

if settings.AUTH2_CLUSTER_ENABLED:
    from .clusterviews import *


if settings.TEST:
    from .testviews import *

