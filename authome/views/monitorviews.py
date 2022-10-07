from django.http import HttpResponse, JsonResponse
from django.conf import settings
from django.utils import timezone
from django.db import transaction

from django_redis import get_redis_connection


import json
import psutil
import traceback
import logging
import os
import socket
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

def _get_localstatus():
    content = OrderedDict()

    content["host"] = socket.gethostname()
    content["pid"] = os.getpid()
    content["starttime"] = utils.get_process_starttime()

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
            cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
            if serverinfo:
                info = " , {}".format(" , ".join("{}={}".format(k,utils.format_datetime(v) if isinstance(v,datetime) else v) for k,v in serverinfo.items()))
            else:
                info = ""

            r = get_redis_connection(name) 
            connection_pool = r.connection_pool

            cache_servers[name] = "server = {} , connections = {} , max connections = {}{}, status = {}".format(utils.print_redisserver(settings.CACHE_SERVER),get_active_redis_connections(name),settings.CACHE_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"),info,cache_msg)
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
                cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
                if serverinfo:
                    info = " , {}".format(" , ".join("{}={}".format(k,utils.format_datetime(v) if isinstance(v,datetime) else v) for k,v in serverinfo.items()))
                else:
                    info = ""

                r = get_redis_connection(name) 
                connection_pool = r.connection_pool
                cache_servers[name] = "server = {} , connections = {} , max connections = {}{} , status = {}".format(utils.print_redisserver(settings.CACHE_USER_SERVER[0]),get_active_redis_connections(name),settings.CACHE_USER_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"),info,cache_msg)
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
                    cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
                    if serverinfo:
                        info = " , {}".format(" , ".join("{}={}".format(k,utils.format_datetime(v) if isinstance(v,datetime) else v) for k,v in serverinfo.items()))
                    else:
                        info = ""

                    r = get_redis_connection(name) 
                    connection_pool = r.connection_pool
                    cache_servers[name] = "server = {} , connections = {} , max connections = {}{} , status = {}".format(utils.print_redisserver(settings.CACHE_USER_SERVER[i]),get_active_redis_connections(name),settings.CACHE_USER_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"),info,cache_msg)
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
                cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
                if serverinfo:
                    info = " , {}".format(" , ".join("{}={}".format(k,utils.format_datetime(v) if isinstance(v,datetime) else v) for k,v in serverinfo.items()))
                else:
                    info = ""

                r = get_redis_connection(name) 
                connection_pool = r.connection_pool
                cache_servers[name] = "server = {} , connections = {} , max connections = {}{} ,  status = {}".format(utils.print_redisserver(settings.CACHE_SESSION_SERVER[0]),get_active_redis_connections(name),settings.CACHE_SESSION_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured") ,info, cache_msg)
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
                    cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
                    if serverinfo:
                        info = " , {}".format(" , ".join("{}={}".format(k,utils.format_datetime(v) if isinstance(v,datetime) else v) for k,v in serverinfo.items()))
                    else:
                        info = ""

                    r = get_redis_connection(name) 
                    connection_pool = r.connection_pool
                    cache_servers[name] = "server:{} , connections:{} , max connections: {}{} , status = {}".format(utils.print_redisserver(settings.CACHE_SESSION_SERVER[i]),get_active_redis_connections(name),settings.CACHE_SESSION_SERVER_OPTIONS.get("CONNECTION_POOL_KWARGS",{}).get("max_connections","Not Configured"),info,cache_msg)
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
    content = _get_localstatus()
    return JsonResponse(content,status=200)

def _clusterstatus(request):
    content = OrderedDict()
    healthy = True
    msgs = {}
    clusters_data = OrderedDict()
    for cluster in models.Auth2Cluster.objects.only("clusterid").order_by("clusterid"):
        if cluster.clusterid == settings.AUTH2_CLUSTERID:
            data = _get_localstatus()
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


def _get_localhealthcheck():
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
            cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
        else:
            cache_healthy,cache_msg = utils.ping_cacheserver(name)
        if not cache_healthy:
            healthy = False
            msgs = utils.add_to_list(msgs,cache_msg)

    if settings.CACHE_USER_SERVER:
        if settings.USER_CACHES  == 1:
            name = "user"
            if settings.CACHE_USER_SERVER[0].lower().startswith("redis"):
                cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
            else:
                cache_healthy,cache_msg = utils.ping_cacheserver(name)

            if not cache_healthy:
                healthy = False
                msgs = utils.add_to_list(msgs,cache_msg)
        else:
            for i in range(settings.USER_CACHES):
                name = "user{}".format(i)
                if settings.CACHE_USER_SERVER[i].lower().startswith("redis"):
                    cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
                else:
                    cache_healthy,cache_msg = utils.ping_cacheserver(name)

                if not cache_healthy:
                    healthy = False
                    msgs = utils.add_to_list(msgs,cache_msg)

    if settings.CACHE_SESSION_SERVER:
        if settings.SESSION_CACHES  == 1:
            name = "session"
            if settings.CACHE_SESSION_SERVER[0].lower().startswith("redis"):
                cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
            else:
                cache_healthy,cache_msg = utils.ping_cacheserver(name)

            if not cache_healthy:
                healthy = False
                msgs = utils.add_to_list(msgs,cache_msg)

        else:
            for i in range(settings.SESSION_CACHES):
                name = "session{}".format(i)
                if settings.CACHE_SESSION_SERVER[i].lower().startswith("redis"):
                    cache_healthy,cache_msg,serverinfo = utils.ping_redisserver(name)
                else:
                    cache_healthy,cache_msg = utils.ping_cacheserver(name)

                if not cache_healthy:
                    healthy = False
                    msgs = utils.add_to_list(msgs,cache_msg)

    return (healthy,msgs)

def _localhealthcheck(request):
    healthy,msgs = _get_localhealthcheck()
    if healthy:
        return HttpResponse("OK")
    else:
        return HttpResponse(status=503,content="\n".join(msgs))

def _remotehealthcheck(request):
    healthy,msgs = _get_localhealthcheck()
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
            cluster_healthy,cluster_msg = _get_localhealthcheck()
        else:
            cluster_healthy,cluster_msg = cache.cluster_healthcheck(cluster.clusterid)
        if not cluster_healthy:
            healthy = False
            msgs[cluster.clusterid] =  cluster_msg

    content["healthy"] = healthy
    if not healthy:
        content["errors"] = msgs
            

    return JsonResponse(content,status=200)

def ping(request):
    healthy,msgs = _get_localhealthcheck()
    if healthy:
        #in healthy status, update heartbeat
        cache._current_auth2_cluster.register(only_update_heartbeat=True)
        return HttpResponse("OK")
    else:
        return HttpResponse(status=503,content="\n".join(msgs))


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


def _sum(d1,d2,excluded_keys=None,included_keys=None):
    if not d2:
        return
    if "requests" in d2 and d2["requests"] == 0:
        return
    for k,v in d2.items():
        if excluded_keys and k in excluded_keys:
            continue
        if included_keys and k not in included_keys:
            continue
        if not v:
            continue
        #convert the domains data to the same data structure when the monitor level is changed
        if k == "domains" and k in d1:
            if isinstance(v,dict):
                if not isinstance(d1[k],dict):
                    #level changed, 
                    d1[k] = {"requests":d1[k]}
            elif isinstance(d1[k],dict):
                #level changed, 
                v = {"requests":v}

        if isinstance(v,dict):
            if k not in d1:
               d1[k] = {}
            elif not isinstance(d1[k],dict):
                d1[k] = {}
            _sum(d1[k],v)
        elif not isinstance(v,(int,float,complex)):
            continue
        elif v <= 0:
            continue
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

def _del_no_requests_data(d):
    for k in [k for k,v in d.items() if not v or (isinstance(v,dict) and "requests" in v and v["requests"] == 0)]:
        del d[k]

    for v in d.values():
        if isinstance(v,dict):
            _del_no_requests_data(v)

sso_requests_keys = {"auth","auth_basic","auth_optional"}
def _save_trafficdata(batchid):
    client = defaultcache.client.get_client()
    trafficdata_key = cache.traffic_data_key

    pdatas = client.lrange(trafficdata_key,0,-1)
    if not pdatas:
        return []

    traffic_datas = {}
    datalength = len(pdatas)
    index = datalength - 1
    for pdata in pdatas:
        if not pdata:
            continue
        pdata = json.loads(pdata)
        pdata["starttime"] = utils.parse_datetime(pdata["starttime"])
        pdata["endtime"] = utils.parse_datetime(pdata["endtime"])
        key = (pdata["starttime"], pdata["endtime"])
        traffic_data = traffic_datas.get(key)
        if not traffic_data:
            traffic_data = {
                "starttime":pdata["starttime"],
                "endtime":pdata["endtime"],
                "sso_requests":{},
                "servers":[pdata["serverid"]]
            }
            traffic_datas[key] = traffic_data
        else:
            traffic_data["servers"].append(pdata["serverid"])
        for method in sso_requests_keys:
            data = pdata.get(method)
            if data:
                _sum(traffic_data["sso_requests"],pdata[method])
        _sum(traffic_data,pdata)

    for data in traffic_datas.values():
        _add_avg(data)
    result = []
    with transaction.atomic():
        #save the data to db
        for data in traffic_datas.values():
            if not data.get("sso_requests",{}).get("requests") and not data.get("get_remote_session",{}).get("requests") and not data.get("delete_remote_session",{}).get("requests"):
                #no requests
                logger.debug("Ignore empty data")
                continue
            traffic_data = models.TrafficData(
                cluster=cache.current_auth2_cluster if settings.AUTH2_CLUSTER_ENABLED else None,
                clusterid=settings.AUTH2_CLUSTERID,
                start_time=data["starttime"],
                end_time=data["endtime"],
                batchid=batchid,
                servers=data["servers"],
                requests=data["sso_requests"].get("requests") or 0,
                total_time=data["sso_requests"].get("totaltime"),
                min_time=data["sso_requests"].get("mintime"),
                max_time=data["sso_requests"].get("maxtime"),
                avg_time=data["sso_requests"].get("avgtime"),
                status=data["sso_requests"].get("status"),
                domains=data["sso_requests"].get("domains"),
                get_remote_sessions = data.get("get_remote_session",{}).get("requests") or 0,
                delete_remote_sessions = data.get("delete_remote_session",{}).get("requests") or 0
            )
            traffic_data.save()
            result.append([utils.encode_datetime(traffic_data.start_time),utils.encode_datetime(traffic_data.end_time),traffic_data.requests,traffic_data.get_remote_sessions,traffic_data.delete_remote_sessions])
            for method,method_data in data.items():
                if method in ("sso_requests","starttime","endtime","servers"):
                    continue
                if not isinstance(method_data,dict) or not method_data.get("requests"):
                    continue

                method_traffic_data = models.SSOMethodTrafficData(
                    traffic_data=traffic_data,
                    sso_method=method,
                    requests=method_data.get("requests"),
                    total_time=method_data.get("totaltime"),
                    min_time=method_data.get("mintime"),
                    max_time=method_data.get("maxtime"),
                    avg_time=method_data.get("avgtime"),
                    status=method_data.get("status"),
                    domains=method_data.get("domains")
                )
                method_traffic_data.save()
        #change the traffic_data process status
        if settings.AUTH2_CLUSTER_ENABLED:
            models.TrafficDataProcessStatus.objects.update_or_create(cluster=cache.current_auth2_cluster,clusterid=settings.AUTH2_CLUSTERID,defaults={"last_saved_batchid":batchid})
        else:
            models.TrafficDataProcessStatus.objects.update_or_create(cluster__isnull=True,clusterid__isnull=True,defaults={"last_saved_batchid":batchid})
        #remove the saved data from cache
        client.ltrim(trafficdata_key,datalength,-1)

    return result


def save_trafficdata(request):
    batchid = request.GET.get("batchid")
    if not batchid:
        return  HttpResponse(content="Missing 'batchid'",status=400)
    try:
        batchid = utils.decode_datetime(batchid)
    except:
        return  HttpResponse(content="Invalid 'batchid'",status=400)

    try:
         result = _save_trafficdata(batchid)
         return  JsonResponse({"result":result},status=200)
    except :
        if settings.AUTH2_CLUSTERID:
            msg = "{} : Failed to save traffic data.{}".format(settings.AUTH2_CLUSTERID,traceback.format_exc())
        else:
            msg = "Failed to save traffic data.{}".format(traceback.format_exc())
        logger.error(msg)
        return HttpResponse(content=msg,status=500)


