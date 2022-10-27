import logging
import traceback

from django.conf import settings
from django.utils import timezone

from ..cache import cache
from .. import utils


logger = logging.getLogger(__name__)

def traffic_monitor(name,func):
    def _monitor(request):
        start = timezone.localtime()
        res = None
        try:
           res = func(request)
           return res
        finally:
            try:
                cache.log_request(name,utils.get_host(request),start,res.status_code if res else 500)
            except:
                logger.error("Failed to log the request.{}".format(traceback.format_exc()))
        
        
    return _monitor if settings.TRAFFIC_MONITOR_LEVEL > 0 else func

