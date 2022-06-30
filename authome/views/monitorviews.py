from django.http import HttpResponse, JsonResponse
from django.template.response import TemplateResponse
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

def status(request):
    content = OrderedDict()

    content["serverid"] = utils.get_processid()
    content["healthy"],msgs = cache.healthy
    if not content["healthy"] :
        content["warning"] = msgs

    content["memory"] = "{}MB".format(round(psutil.Process().memory_info().rss / (1024 * 1024),2))
    redis_servers = OrderedDict()
    content["redis server"] = redis_servers
    if settings.CACHE_USER_SERVER:
        if settings.USER_CACHES  == 1:
            if settings.CACHE_USER_SERVER[0].lower().startswith("redis"):
                name = "user"
                r = get_redis_connection(name) 
                connection_pool = r.connection_pool
                redis_servers[name] = "server:{} , connections:{} , max connections: {}".format(settings.CACHE_USER_SERVER[0],get_active_redis_connections(name),settings.CACHE_USER_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"))
        else:
            for i in range(settings.USER_CACHES):
                if not settings.CACHE_USER_SERVER[i].lower().startswith("redis"):
                    continue
                name = "user{}".format(i)
                r = get_redis_connection(name) 
                connection_pool = r.connection_pool
                redis_servers[name] = "server:{} , connections:{} , max connections: {}".format(settings.CACHE_USER_SERVER[i],get_active_redis_connections(name),settings.CACHE_USER_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"))

    if settings.CACHE_SESSION_SERVER:
        if settings.SESSION_CACHES  == 1:
            if settings.CACHE_SESSION_SERVER[0].lower().startswith("redis"):
                name = "session"
                r = get_redis_connection(name) 
                connection_pool = r.connection_pool
                redis_servers[name] = "server:{} , connections:{} , max connections: {}".format(settings.CACHE_SESSION_SERVER[0],get_active_redis_connections(name),settings.CACHE_SESSION_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"))
        else:
            for i in range(settings.SESSION_CACHES):
                if not settings.CACHE_SESSION_SERVER[i].lower().startswith("redis"):
                    continue
                name = "session{}".format(i)
                r = get_redis_connection(name) 
                connection_pool = r.connection_pool
                redis_servers[name] = "server:{} , connections:{} , max connections: {}".format(settings.CACHE_SESSION_SERVER[i],get_active_redis_connections(name),settings.CACHE_SESSION_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"))

    if settings.CACHE_SERVER and settings.CACHE_SERVER.lower().startswith("redis"):
        name = "default"
        r = get_redis_connection(name) 
        connection_pool = r.connection_pool
        redis_servers[name] = "server:{} , connections:{} , max connections: {}".format(settings.CACHE_SERVER,get_active_redis_connections(name),settings.CACHE_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"))

    content["memorycache"] = cache.status
    content = json.dumps(content)
    return HttpResponse(content=content,content_type="application/json")

def healthcheck(request):
    healthy,msgs = cache.healthy
    if healthy:
        return HttpResponse("ok")
    else:
        return HttpResponse(status=503,content="\n".join(msgs))

def checkauthorization(request):
    if request.method == "GET":
        return TemplateResponse(request, "authome/check_authorization.html", {"users":"","opts":None})

    try:
        default_domain = utils.get_host(request)
        urls = request.POST["url"]
        users = request.POST["user"]
        details = request.POST.get("details","false").lower() == "true"
        flaturl = request.POST.get("flaturl","false").lower() == "true"
        flatuser = request.POST.get("flatuser","false").lower() == "true"

        if urls:
            urls = [u.strip() for u in urls.split(",") if u.strip()]
        if users:
            users = [u.strip() for u in users.split(",") if u.strip() and "@"  in u]
    
        if not urls:
            return HttpResponse(status=400,content="URL is empty")
        if not users:
            return HttpResponse(status=400,content="User is empty")
    
        urls = [ utils.parse_url(u) for u in urls]
        for url in urls:
            if not url["domain"]:
                url["domain"] = default_domain
            if not url["path"] :
                url["path"] = "/"
            url["checked_url"] = "{}{}{}".format(url["domain"],":{}".format(url["port"]) if url["port"] else "",url["path"])

        result = []
        for user in users:
            if flaturl and len(urls) == 1:
                url = urls[0]
                if details:
                    check_result = models.check_authorization(user,url["domain"] ,url["path"])
                    #check result is a tupe (Allow?,[(usergroup,checkgroup,allow?),]), change the usergroup to the name of user group
                    for i in range(len(check_result[1])):
                        check_result[1][i] = [check_result[1][i][0].name if check_result[1][i][0] else None,check_result[1][i][1].name if check_result[1][i][1] else None,check_result[1][i][2]]
                    
                    result.append([user,url["url"],url["checked_url"],check_result])
                elif url["path"].startswith("/sso/"):
                    result.append([user,url["url"],url["checked_url"],True ])
                else:
                    result.append([user,url["url"],url["checked_url"],models.can_access(user,url["domain"] ,url["path"]) ])
            else:
                userresult = {}
                result.append((user,userresult))
                for url in urls:
                    if details:
                        check_result = models.check_authorization(user,url["domain"] ,url["path"] )
                        #check result is a tupe (Allow?,[(usergroup,checkgroup,allow?),]), change the usergroup to the name of user group
                        for i in range(len(check_result[1])):
                            check_result[1][i] = [check_result[1][i][0].name if check_result[1][i][0] else None,check_result[1][i][1].name if check_result[1][i][1] else None,check_result[1][i][2]]
                    
                        userresult[url["url"]] = [url["checked_url"],check_result]
                    elif url["path"].startswith("/sso/"):
                        userresult[url["url"]] = [url["checked_url"],True]
                    else:
                        userresult[url["url"]] = [url["checked_url"],models.can_access(user,url["domain"],url["path"] )]

        if flatuser and len(users) == 1:
            result = result[0]

        return HttpResponse(content=json.dumps(result),content_type="application/json")
    except Exception as ex:
        traceback.print_exc()
        return HttpResponse(status=400,content=str(ex))

def echo(request):
    data = OrderedDict()
    data["url"] = "https://{}{}".format(utils.get_host(request),request.get_full_path())
    data["method"] = request.method
    
    keys = [k for k in request.GET.keys()]
    keys.sort()
    if keys:
        data["parameters"] = OrderedDict()
    for k in keys:
        v = request.GET.getlist(k)
        if not v:
            data["parameters"][k] = v
        elif len(v) == 1:
            data["parameters"][k] = v[0]
        else:
            data["parameters"][k] = v

    keys = [k for k in request.COOKIES.keys()]
    keys.sort()
    if keys:
        data["cookies"] = OrderedDict()
    for k in keys:
        v = request.COOKIES[k]
        data["cookies"][k] = v


    keys = [k for k in request.headers.keys()]
    keys.sort()
    if keys:
        data["headers"] = OrderedDict()
    for k in keys:
        v = request.headers[k]
        data["headers"][k.lower()] = v

    if request.method == "POST":
        data["body"] = OrderedDict()
        keys = [k for k in request.POST.keys()]
        keys.sort()
        for k in keys:
            v = request.POST.getlist(k)
            if not v:
                data["body"][k] = v
            elif len(v) == 1:
                data["body"][k] = v[0]
            else:
                data["body"][k] = v

    return JsonResponse(data,status=200)

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



