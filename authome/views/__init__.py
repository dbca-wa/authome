from django.conf import settings

from .views import *
from .monitorviews import *
from ..cache import cache
from . import selfservice
from .tools import *

if settings.AUTH2_CLUSTER_ENABLED:
    from .clusterviews import *


if settings.TESTMODE:
    from .testviews import *

