import atexit

from django.conf import settings
from django.utils import timezone

from .cache import get_usercache,get_defaultcache,defaultcache,IntervalTaskRunable,HourListTaskRunable

if settings.AUTH2_CLUSTERID:
    from .clustercache import MemoryCache
    cache = MemoryCache()
elif settings.TRAFFICCONTROL_ENABLED:
    from .tcontrolcache import MemoryCache
    cache = MemoryCache()
else:
    from .cache import MemoryCache
    cache = MemoryCache()

if settings.TRAFFIC_MONITOR_LEVEL > 0:
    def save_traffic_data():
        if defaultcache:
            cache._save_traffic_data(timezone.localtime())

    atexit.register(save_traffic_data)
