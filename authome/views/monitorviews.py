from django.http import HttpResponse, JsonResponse
from django.conf import settings
from django.utils import timezone

from django_redis import get_redis_connection


import json
import psutil
import traceback
import logging
from collections import OrderedDict
from datetime import datetime,timedelta

from .. import models
from ..cache import cache,get_defaultcache
from .. import utils


defaultcache = get_defaultcache()

logger = logging.getLogger(__name__)

def get_active_redis_connections(cachename):
    r = get_redis_connection(cachename) 
    connection_pool = r.connection_pool
    return connection_pool._created_connections

def _get_localstatus(request):
    content = OrderedDict()

    if settings.AUTH2_CLUSTER_ENABLED:
        content["clusterid"] = settings.AUTH2_CLUSTERID
        content["default_cluster"] = settings.DEFAULT_AUTH2_CLUSTER
        content["endpoint"] = cache._current_auth2_cluster.endpoint

    healthy = True
    msgs = []

    databases = OrderedDict()
    for n,d in settings.DATABASES.items():
        db = "{}:{}/{}".format(d["HOST"],d["PORT"],d["NAME"])
        db_healthy,db_msg = utils.ping_database(n)
        databases[n] = "server = {}:{}/{} , status = {}".format(d["HOST"],d["PORT"],d["NAME"],db_msg)
        if not db_healthy:
            healthy = False
            msgs = utils.add_to_list(msgs,db_msg)

    cache_servers = OrderedDict()
    if settings.CACHE_SERVER:
        name = "default"
        if settings.CACHE_SERVER.lower().startswith("redis"):
            cache_healthy,cache_msg = utils.ping_redisserver(name)
            r = get_redis_connection(name) 
            connection_pool = r.connection_pool
            cache_servers[name] = "server = {} , connections = {} , max connections = {} , status = {}".format(settings.CACHE_SERVER,get_active_redis_connections(name),settings.CACHE_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"),cache_msg)
        else:
            cache_healthy,cache_msg = utils.ping_cacheserver(name)
            cache_servers[name] = "server = {} ,  status = {}".format(settings.CACHE_SERVER,cache_msg)
        if not cache_healthy:
            healthy = False
            msgs = utils.add_to_list(msgs,cache_msg)

    if settings.CACHE_USER_SERVER:
        if settings.USER_CACHES  == 1:
            name = "user"
            if settings.CACHE_USER_SERVER[0].lower().startswith("redis"):
                cache_healthy,cache_msg = utils.ping_redisserver(name)
                r = get_redis_connection(name) 
                connection_pool = r.connection_pool
                cache_servers[name] = "server = {} , connections = {} , max connections = {} , status = {}".format(settings.CACHE_USER_SERVER[0],get_active_redis_connections(name),settings.CACHE_USER_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"),cache_msg)
            else:
                cache_healthy,cache_msg = utils.ping_cacheserver(name)
                cache_servers[name] = "server = {} ,  status = {}".format(settings.CACHE_USER_SERVER[0],cache_msg)

            if not cache_healthy:
                healthy = False
                msgs = utils.add_to_list(msgs,cache_msg)
        else:
            for i in range(settings.USER_CACHES):
                name = "user{}".format(i)
                if settings.CACHE_USER_SERVER[i].lower().startswith("redis"):
                    cache_healthy,cache_msg = utils.ping_redisserver(name)
                    r = get_redis_connection(name) 
                    connection_pool = r.connection_pool
                    cache_servers[name] = "server = {} , connections = {} , max connections = {} , status = {}".format(settings.CACHE_USER_SERVER[i],get_active_redis_connections(name),settings.CACHE_USER_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"),cache_msg)
                else:
                    cache_healthy,cache_msg = utils.ping_cacheserver(name)
                    cache_servers[name] = "server = {} ,  status = {}".format(settings.CACHE_USER_SERVER[i],cache_msg)

                if not cache_healthy:
                    healthy = False
                    msgs = utils.add_to_list(msgs,cache_msg)

    if settings.CACHE_SESSION_SERVER:
        if settings.SESSION_CACHES  == 1:
            name = "session"
            if settings.CACHE_SESSION_SERVER[0].lower().startswith("redis"):
                cache_healthy,cache_msg = utils.ping_redisserver(name)
                r = get_redis_connection(name) 
                connection_pool = r.connection_pool
                cache_servers[name] = "server = {} , connections = {} , max connections = {} ,  status = {}".format(settings.CACHE_SESSION_SERVER[0],get_active_redis_connections(name),settings.CACHE_SESSION_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured") , cache_msg)
            else:
                cache_healthy,cache_msg = utils.ping_cacheserver(name)
                cache_servers[name] = "server = {} ,  status = {}".format(settings.CACHE_SESSION_SERVER[0],cache_msg)

            if not cache_healthy:
                healthy = False
                msgs = utils.add_to_list(msgs,cache_msg)

        else:
            for i in range(settings.SESSION_CACHES):
                name = "session{}".format(i)
                if settings.CACHE_SESSION_SERVER[i].lower().startswith("redis"):
                    cache_healthy,cache_msg = utils.ping_redisserver(name)
                    r = get_redis_connection(name) 
                    connection_pool = r.connection_pool
                    cache_servers[name] = "server:{} , connections:{} , max connections: {}".format(settings.CACHE_SESSION_SERVER[i],get_active_redis_connections(name),settings.CACHE_SESSION_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"))
                else:
                    cache_healthy,cache_msg = utils.ping_cacheserver(name)
                    cache_servers[name] = "server = {} ,  status = {}".format(CACHE_SESSION_SERVER[i],cache_msg)

                if not cache_healthy:
                    healthy = False
                    msgs = utils.add_to_list(msgs,cache_msg)

    cache_healthy,cache_msgs = cache.healthy
    healthy = healthy and cache_healthy
    if not cache_healthy:
        msgs = utils.add_to_list(msgs,cache_msgs)
    content["healthy"] = healthy
    if not healthy :
        content["errors"] = msgs

    content["memory"] = "{}MB".format(round(psutil.Process().memory_info().rss / (1024 * 1024),2))

    content["modelcachestatus"] = {}

    for cls in (models.UserGroup,models.UserGroupAuthorization,models.CustomizableUserflow,models.IdentityProvider):
        content["modelcachestatus"][cls.__name__] = models.CACHE_STATUS_NAME[cls.cache_status()]

    content["databases"] = databases

    content["cache server"] = cache_servers

    content["memorycache"] = cache.status

    content["serverid"] = utils.get_processid()
    return content

def _localstatus(request):
    content = _get_localstatus(request)
    return JsonResponse(content,status=200)

def _clusterstatus(request):
    content = OrderedDict()
    healthy = True
    msgs = {}
    clusters_data = OrderedDict()
    for cluster in models.Auth2Cluster.objects.only("clusterid").order_by("clusterid"):
        if cluster.clusterid == settings.AUTH2_CLUSTERID:
            data = _get_localstatus(request)
        else:
            data = cache.get_cluster_status(cluster.clusterid)
        clusters_data[cluster.clusterid] = data
        if not data["healthy"]:
            healthy = False
            msgs[cluster.clusterid] = data["errors"]

    content["healthy"] = healthy
    if not healthy:
        content["errors"] = msgs
            

    content["clusters"] = clusters_data
    return JsonResponse(content,status=200)

def statusfactory(t=None):
    if t:
        if t == "local":
            return  _localstatus
        else:
            return _clusterstatus

    elif settings.AUTH2_CLUSTER_ENABLED:
        return _clusterstatus
    else:
        return  _localstatus


def _get_localhealthcheck(request):
    healthy = True
    msgs = []

    for n,d in settings.DATABASES.items():
        db_healthy,db_msg = utils.ping_database(n)
        if not db_healthy:
            healthy = False
            msgs = utils.add_to_list(msgs,db_msg)

    if settings.CACHE_SERVER:
        name = "default"
        if settings.CACHE_SERVER.lower().startswith("redis"):
            cache_healthy,cache_msg = utils.ping_redisserver(name)
        else:
            cache_healthy,cache_msg = utils.ping_cacheserver(name)
        if not cache_healthy:
            healthy = False
            msgs = utils.add_to_list(msgs,cache_msg)

    if settings.CACHE_USER_SERVER:
        if settings.USER_CACHES  == 1:
            name = "user"
            if settings.CACHE_USER_SERVER[0].lower().startswith("redis"):
                cache_healthy,cache_msg = utils.ping_redisserver(name)
            else:
                cache_healthy,cache_msg = utils.ping_cacheserver(name)

            if not cache_healthy:
                healthy = False
                msgs = utils.add_to_list(msgs,cache_msg)
        else:
            for i in range(settings.USER_CACHES):
                name = "user{}".format(i)
                if settings.CACHE_USER_SERVER[i].lower().startswith("redis"):
                    cache_healthy,cache_msg = utils.ping_redisserver(name)
                else:
                    cache_healthy,cache_msg = utils.ping_cacheserver(name)

                if not cache_healthy:
                    healthy = False
                    msgs = utils.add_to_list(msgs,cache_msg)

    if settings.CACHE_SESSION_SERVER:
        if settings.SESSION_CACHES  == 1:
            name = "session"
            if settings.CACHE_SESSION_SERVER[0].lower().startswith("redis"):
                cache_healthy,cache_msg = utils.ping_redisserver(name)
            else:
                cache_healthy,cache_msg = utils.ping_cacheserver(name)

            if not cache_healthy:
                healthy = False
                msgs = utils.add_to_list(msgs,cache_msg)

        else:
            for i in range(settings.SESSION_CACHES):
                name = "session{}".format(i)
                if settings.CACHE_SESSION_SERVER[i].lower().startswith("redis"):
                    cache_healthy,cache_msg = utils.ping_redisserver(name)
                else:
                    cache_healthy,cache_msg = utils.ping_cacheserver(name)

                if not cache_healthy:
                    healthy = False
                    msgs = utils.add_to_list(msgs,cache_msg)

    return (healthy,msgs)

def _localhealthcheck(request):
    healthy,msgs = _get_localhealthcheck(request)
    if healthy:
        return HttpResponse("OK")
    else:
        return HttpResponse(status=503,content="\n".join(msgs))

def _remotehealthcheck(request):
    healthy,msgs = _get_localhealthcheck(request)
    data = {"healthy":healthy}
    if not healthy:
        data["errors"] = msgs
    return JsonResponse(data,status=200)

def _clusterhealthcheck(request):
    healthy = True
    msgs = {}
    content = {}
    for cluster in models.Auth2Cluster.objects.only("clusterid").order_by("clusterid"):
        if cluster.clusterid == settings.AUTH2_CLUSTERID:
            cluster_healthy,cluster_msg = _get_localhealthcheck(request)
        else:
            cluster_healthy,cluster_msg = cache.cluster_healthcheck(cluster.clusterid)
        if not cluster_healthy:
            healthy = False
            msgs[cluster.clusterid] =  cluster_msg

    content["healthy"] = healthy
    if not healthy:
        content["errors"] = msgs
            

    return JsonResponse(content,status=200)

def healthcheckfactory(t=None):
    if t:
        if t == "local":
            return  _localhealthcheck
        elif t == "remote":
            return  _remotehealthcheck
        else:
            return _clusterhealthcheck

    elif settings.AUTH2_CLUSTER_ENABLED:
        return _clusterhealthcheck
    else:
        return  _localhealthcheck


def _sum(d1,d2,excluded_keys=None):
    if "requests" in d2 and d2["requests"] == 0:
        return
    for k,v in d2.items():
        if excluded_keys and k in excluded_keys:
            continue
        if isinstance(v,dict):
            if k not in d1:
               d1[k] = {}
            _sum(d1[k],v)
        elif v <= 0:
            pass
        elif k not in d1:
            d1[k] = v
        elif k.startswith("min"):
            if d1[k] <= 0 or d1[k] > v:
                d1[k] = v
        elif k.startswith("max"):
            if d1[k] < v:
                d1[k] = v
        else:
            d1[k] = (d1[k] or 0) + (v or 0)
def _add_avg(d):
    if all(k in d for k in ("requests","totaltime")):
        if d["requests"]:
            d["avgtime"] = d["totaltime"] / d["requests"]
        else:
            d["avgtime"] = 0

    for v in d.values():
        if isinstance(v,dict):
            _add_avg(v)

def _get_localtrafficmonitor(request):
    #level 1: only show the summary, 2: summary, time based summary, 3: summary , time based summary and server process based data
    client = defaultcache.client.get_client()

    now = timezone.localtime()
    today = datetime(now.year,now.month,now.day,tzinfo=now.tzinfo)

    try:
        level = int(request.GET.get("level",1))
    except:
        level = 1

    start_data_ts = None

    hours = request.GET.get("hours")
    if hours:
        try:
            hours = int(hours)
            if hours > 0:
                seconds_in_day = (now - today).seconds - hours * 3600
                start_data_ts = today + timedelta(seconds =  seconds_in_day - seconds_in_day % settings.TRAFFIC_MONITOR_INTERVAL.seconds)
        except:
            pass

    if not start_data_ts:
        try:
            start_time = request.GET.get("starttime")
            if start_time:
                start_time = timezone.make_aware(datetime.strptime(start_time,"%Y-%m-%d %H:%M:%S"))
                start_day = datetime(start_time.year,start_time.month,start_time.day,tzinfo=start_time.tzinfo)
                seconds_in_day = (start_time - start_day).seconds
                start_data_ts = start_day + timedelta(seconds =  seconds_in_day - seconds_in_day % settings.TRAFFIC_MONITOR_INTERVAL.seconds)
            else:
                start_data_ts = today
        except:
            start_data_ts = today

    end_data_ts = None
    try:
        end_time = request.GET.get("endtime")
        if end_time:
            end_time = timezone.make_aware(datetime.strptime(end_time,"%Y-%m-%d %H:%M:%S"))
            end_day = datetime(end_time.year,end_time.month,end_time.day,tzinfo=end_time.tzinfo)
            seconds_in_day = (end_time - end_day).seconds
            end_data_ts = end_day + timedelta(seconds =  seconds_in_day - seconds_in_day % settings.TRAFFIC_MONITOR_INTERVAL.seconds)
    except:
        pass

    if not end_data_ts:
        seconds_in_day = (now - today).seconds
        end_data_ts = today + timedelta(seconds =  seconds_in_day - seconds_in_day % settings.TRAFFIC_MONITOR_INTERVAL.seconds - settings.TRAFFIC_MONITOR_INTERVAL.seconds)

    data = OrderedDict()
    data_ts = start_data_ts
    data["starttime"] = utils.format_datetime(start_data_ts)
    data["endtime"] = utils.format_datetime(end_data_ts)
    if settings.TRAFFIC_MONITOR_LEVEL <= 0:
        data["traffic_monitor_enabled"] = False
        return (level,start_data_ts,end_data_ts,data)

    times_data = OrderedDict()

    while data_ts <= end_data_ts:
        try:
            key = cache.traffic_data_key_pattern.format(data_ts.strftime("%Y%m%d%H%M"))
            pdatas = client.lrange(key,0,-1)
            if not pdatas:
                continue

            index = len(pdatas) - 1
            while index >= 0:
                if not pdatas[index]:
                    del pdatas[index]
                else:
                    pdatas[index] = json.loads(pdatas[index])
                index -= 1
                
            pdatas.sort(key=lambda o:o["serverid"])

            time_data = OrderedDict()
            servers_data = OrderedDict()
            if level > 1:
                times_data[ utils.format_datetime(data_ts)] = time_data
            for pdata in pdatas:
                serverid = pdata.pop("serverid")
                _sum(time_data,pdata)
                if level > 2:
                    if serverid in servers_data:
                        i = 1
                        while True:
                            key = "{}.{}".format(serverid,i)
                            if key in servers_data:
                                i += 1
                            else:
                                servers_data[key] = pdata
                                break
                    else:
                        servers_data[serverid] = pdata
            _sum(data,time_data)
            if level > 2:
                time_data["servers"] = servers_data
        finally:
            data_ts += settings.TRAFFIC_MONITOR_INTERVAL
    if level > 1:
        data["times"] = times_data
    _add_avg(data)

    return (level,start_data_ts,end_data_ts,data)

def _localtrafficmonitor(request):
    level,start_data_ts,end_data_ts,data = _get_localtrafficmonitor(request)

    return JsonResponse(data,status=200)

def _clusterstrafficmonitor(request):
    result = OrderedDict()
    level,start_data_ts,end_data_ts,data = _get_localtrafficmonitor(request)
    result["starttime"] = data.pop("starttime")
    result["endtime"] = data.pop("endtime")
    _sum(result,data,excluded_keys=("avgtime","times"))
    result["clusters"] = OrderedDict()
    result["clusters"][settings.AUTH2_CLUSTERID] = data
    for c in cache.auth2_clusters.values():
        try:
            data = cache.get_traffic_data(c.clusterid,level,start_data_ts,end_data_ts)
            del data["starttime"]
            del data["endtime"]
            _sum(result,data,excluded_keys=("avgtime","times","traffic_monitor_enabled"))
        except Exception as ex:
            data["exception"] = str(ex)
        result["clusters"][settings.AUTH2_CLUSTERID] = data

    _add_avg(result)
    return JsonResponse(result,status=200)

def trafficmonitorfactory(t=None):
    if t:
        if t == "local":
            return  _localtrafficmonitor
        else:
            return _clusterstrafficmonitor

    elif settings.AUTH2_CLUSTER_ENABLED:
        return _clusterstrafficmonitor
    else:
        return  _localtrafficmonitor



