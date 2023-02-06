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

_requests = 0
def traffic_monitor_debug(name,func):
    def _monitor(request):
        global _requests
        start = timezone.localtime()
        _requests += 1
        res = None
        try:
           res = func(request)
           return res
        finally:
            try:
                cache.log_request(name,utils.get_host(request),start,res.status_code if res else 500)
            except:
                logger.error("Failed to log the request.{}".format(traceback.format_exc()))
            data = {}
            for k,v in  cache._traffic_data.items():
                if not isinstance(v,dict) or "domains" not in v:
                    continue
                for d,r in v["domains"].items():
                    data[d] = data.get(d,0) + r

            logger.warning("{} - {}: requests={} , request = {}, traffic_data={}".format(utils.format_datetime(start),utils.get_threadid(),_requests,"{}{}".format(utils.get_host(request),request.path),data ))
        
        
    return _monitor if settings.TRAFFIC_MONITOR_LEVEL > 0 else func

