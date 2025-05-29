
import logging
from django.conf import settings

from .cache  import IntervalTaskRunable
from .cache  import MemoryCache as BaseMemoryCache

logger = logging.getLogger(__name__)

class MemoryCache(BaseMemoryCache):
    def __init__(self):
        super().__init__()
        #model TrafficControl cache
        self._tcontrols = None
        self._tcontrols_size = None
        self._tcontrols_ts = None

        #The runable task to check TrafficControl cache
        self._tcontrol_cache_check_time = IntervalTaskRunable("traffic control cache",settings.TRAFFICCONTROL_CACHE_CHECK_INTERVAL) if settings.TRAFFICCONTROL_CACHE_CHECK_INTERVAL > 0 else HourListTaskRunable("traffic control cache",settings.TRAFFICCONTROL_CACHE_CHECK_HOURS)

    def refresh_tcontrol_cache(self,force=False):
        if not self._tcontrols:
            from ..models import TrafficControl
            self._tcontrol_cache_check_time.can_run()
            TrafficControl.refresh_cache()
        elif self._tcontrol_cache_check_time.can_run() or force:
            from ..models import TrafficControlChange,TrafficControl
            if TrafficControlChange.is_changed():
                TrafficControl.refresh_cache()

    @property
    def tcontrols(self):
        self.refresh_tcontrol_cache()
        return self._tcontrols

    @tcontrols.setter
    def tcontrols(self,value):
        if value:
            self._tcontrols,self._tcontrols_size,self._tcontrols_ts = value
        else:
            self._tcontrols,self._tcontrols_size,self._tcontrols_ts = None,None,None

