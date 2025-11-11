import logging
import traceback

from django.conf import settings
from django.utils import timezone

from ..cache import cache
from .. import utils
from authome.models import DebugLog
from ..views import auth_basic

logger = logging.getLogger(__name__)

def traffic_monitor(name,func,slowrequestenabled=True):
    def _monitor(request):
        start = timezone.localtime()
        res = None
        try:
           res = func(request)
           return res
        finally:
            try:
                ptime = cache.log_request(name,request.get_host(),start,res.status_code if res else 500) 
                if slowrequestenabled and ptime > settings.AUTH_TOO_SLOW_THRESHOLD:
                    try:
                        useremail = request.user.email
                    except:
                        useremail = None
                    DebugLog.warning(
                        DebugLog.AUTH_TOO_SLOW,
                        utils.get_source_lb_hash_key(request),
                        utils.get_source_clusterid(request),
                        utils.get_source_session_key(request),
                        utils.get_source_session_cookie(request),
                        useremail=useremail,
                        message="Authentication method({}) is too slow.process time = {}/{} milliseconds, status code = {}" .format(name,ptime,settings.AUTH_TOO_SLOW_THRESHOLD,res.status_code if res else 500)
                    )

            except:
                logger.error("Failed to log the request.{}".format(traceback.format_exc()))
        
    return _monitor if settings.TRAFFIC_MONITOR_LEVEL > 0 else func

def basic_auth_wrapper(func):
    def _func(request,*args,**kwargs):
        res = auth_basic(request)
        if res.status_code >= 300:
            return res
        return func(request,*args,**kwargs)

    return _func
        
"""
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
                cache.log_request(name,request.get_host(),start,res.status_code if res else 500)
            except:
                logger.error("Failed to log the request.{}".format(traceback.format_exc()))
            data = {}
            for k,v in  cache._traffic_data.items():
                if not isinstance(v,dict) or "domains" not in v:
                    continue
                for d,r in v["domains"].items():
                    data[d] = data.get(d,0) + r

            logger.warning("{} - {}: requests={} , request = {}, traffic_data={}".format(utils.format_datetime(start),utils.get_threadid(),_requests,"{}{}".format(request.get_host(),request.path),data ))
        
        
    return _monitor if settings.TRAFFIC_MONITOR_LEVEL > 0 else func
"""
