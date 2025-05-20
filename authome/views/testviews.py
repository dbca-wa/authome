import re
import time
import logging
import json
from collections import OrderedDict
from datetime import datetime,timedelta

from django.utils import timezone
from django.contrib.auth import login
from django.http import HttpResponse, JsonResponse
from django.conf import settings

from . import views
from .. import models
from .. import utils
from ..sessionstore.sessionstore import SessionStore 
from ..serializers import JSONEncoder,JSONFormater
from .. import trafficdata
from ..cache import cache, get_defaultcache
from django.db import connections

defaultcache = get_defaultcache()

if settings.AUTH2_CLUSTER_ENABLED:
    from ..sessionstore.clustersessionstore import SessionStore as ClusterSessionStore
    from ..sessionstore.clustersessionstore import StandaloneSessionStore

logger = logging.getLogger(__name__)

def login_user(request):
    email = request.GET.get("user")
    if not email:
        return HttpResponse(status=400,content="Parameter 'user' is missing.")
    enabletoken = (request.GET.get("enabletoken") or "true").lower() == "true"
    refreshtoken = (request.GET.get("refreshtoken") or "false").lower() == "true"

    user = models.User.objects.filter(email=email).first()
    if not user:
        name = email.split("@",1)[0]
        nameparts = None
        firstname = name
        lastname = "test"
        for sep in [".","_","-"]:
            nameparts = name.split("_",1)
            if len(nameparts) == 1:
                continue
            elif sep == ".":
                firstname,lastname = nameparts
                break
            else :
                lastname,firstname = nameparts
                break

        dbcagroup = models.UserGroup.dbca_group()
        usergroups = models.UserGroup.find_groups(email)[0]
        if any(group.is_group(dbcagroup) for group in usergroups ):
            is_staff = True
        else:
            is_staff = False
    else:
        firstname = user.first_name
        lastname = user.last_name
        is_staff = user.is_staff

    idp,created = models.IdentityProvider.objects.get_or_create(idp=models.IdentityProvider.AUTH_EMAIL_VERIFY[0],defaults={"name":models.IdentityProvider.AUTH_EMAIL_VERIFY[1]})
    user,created = models.User.objects.update_or_create(email=email,username=email,defaults={"is_staff":is_staff,"last_idp":idp,"last_login":timezone.localtime(),"first_name":firstname,"last_name":lastname,"is_active":True})

    #enable user token
    token = models.UserToken.objects.filter(user=user).first()
    if enabletoken:
        changed = False
        if not token:
            token = models.UserToken(user=user)
            token.enabled = True
            token.generate_token()
            changed = True
        else:
            if not token.enabled:
                token.enabled = True
                changed = True
            if not token.token or token.is_expired or refreshtoken:
                token.generate_token()
                chaged = True
        if changed:
            token.save()
    else:
        if token and token.enabled:
            token.enabled = False
            token.save(update_fields=["enabled"])

    request.session["idp"] = idp.idp
    login(request,user,'django.contrib.auth.backends.ModelBackend')
    request.session["idp"] = idp.idp
    usergroups = models.UserGroup.find_groups(email)[0]
    timeout = models.UserGroup.get_session_timeout(usergroups)
    if timeout:
        request.session["session_timeout"] = timeout

    return views.profile(request)

def pseudo_auth(logics):
    if not logics:
        return []
    processdata = []
    for logic in logics:
        method = logic[0] if logic[0] else "computing"
        if logic[1] <= 0:
            continue
        starttime = timezone.localtime()
        if method == "sleep":
            time.sleep(logic[1])
        elif method == "db":
            with connections["default"].cursor() as cursor:
                try:
                    cursor.execute("select pg_sleep({})".format(logic[1]))
                except Exception as ex:
                    pass
        elif method == "redis":
            defaultcacheclient = defaultcache.redis_client
            defaultcacheclient.execute_command("blpop","__does_not_exist__",logic[1])
        elif method == "computing":
            if settings.SYNC_MODE == "eventlet":
                import eventlet
                eventlet.patcher.original('time').sleep(logic[1])
            elif settings.SYNC_MODE == "gevent":
                import gevent
                gevent.monkey.get_original("time","sleep")(logic[1])
            else:
                time.sleep(logic[1])
        else:
            method = "sleep"
            time.sleep(logic[1])
        endtime = timezone.localtime()
        processdata.append((method,logic[1],starttime,endtime))
    return processdata

def echo(request):
    logics = request.GET.get("logic")
    if logics:
        logics = [d.strip().split(".",1) if "." in d else ["computing",d] for d in logics.split(",") if d.strip()]
        for logic in logics:
            logic[0] = logic[0].lower()
            logic[1] = float(logic[1])

    processdata = pseudo_auth(logics)

    data = OrderedDict()
    data["url"] = "https://{}{}".format(request.get_host(),request.get_full_path())
    data["method"] = request.method
    if processdata:
        data["processing"] = []
    for d in processdata:
        data["processing"].append("{2} - {3} : {0}({1} seconds)".format(d[0],d[1],d[2].strftime("%Y-%m-%dT%H:%M:%S.%f"),d[3].strftime("%Y-%m-%dT%H:%M:%S.%f")))
    
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

def get_settings(request):
    try:
        names = request.GET.get("names").split(",")
        data = {}
        for name in names:
            if hasattr(settings,name):
                val = getattr(settings,name)
                if isinstance(val,datetime):
                    data[name] = utils.encode_datetime(val)
                elif isinstance(val,timedelta):
                    data[name] = utils.encode_timedelta(val)
                else:
                    data[name] = val
            else:
                data[name] = None
        return JsonResponse(data,status=200)
    except Exception as ex:
        logger.error("Failed to get settings({}).{} ".format(names,str(ex)))
        raise


def get_session(request):
    """
    Get the session data from the session cache without previous session cache support.
    """
    try:
        session_cookie = request.GET.get("session")
        if not session_cookie:
            return  views.response_not_found_factory(request)
    
        values = session_cookie.split("|")
        if len(values) == 1:
            session_key = values[0]
            values = session_key.rsplit(settings.SESSION_COOKIE_DOMAIN_SEPARATOR,1)
            if len(values) == 1:
                cookie_domain = None
                session_key = values[0]
            else:
                session_key,cookie_domain = values
            if settings.AUTH2_CLUSTER_ENABLED:
                sessionstore = StandaloneSessionStore(session_key)
            else:
                sessionstore = SessionStore(session_key,cookie_domain=cookie_domain)
        else:
            lb_hash_key,auth2_clusterid,signature,session_key = values
            values = session_key.rsplit(settings.SESSION_COOKIE_DOMAIN_SEPARATOR,1)
            if len(values) == 1:
                cookie_domain = None
                session_key = values[0]
            else:
                session_key,cookie_domain = values
            sessionstore = ClusterSessionStore(lb_hash_key,auth2_clusterid,session_key,cookie_domain=cookie_domain)
    
        sessioncache = sessionstore._get_cache()
        cachekey = sessionstore.cache_key
        session_data = sessioncache.get(cachekey)
        if session_data:
            ttl = sessionstore.ttl
            return JsonResponse({"session":session_data,"ttl":ttl},status=200)
        else:
            return  views.response_not_found_factory(request)
    except Exception as ex:
        logger.error("Failed to get session({}) from cache.{} ".format(session_cookie,str(ex)))
        raise

def flush_trafficdata(requests):
    if cache._traffic_data and len(cache._traffic_data) > 1:
        cache._save_traffic_data(timezone.localtime())
        cache._traffic_data.clear()
        cache._traffic_data["serverid"] = utils.get_processid()
        return JsonResponse({"flushed":True,"server":utils.get_processid()},status=200,encoder=JSONEncoder)
    else:
        return JsonResponse({"flushed":False,"server":utils.get_processid()},status=200,encoder=JSONEncoder)
    
def save_trafficdata_to_db(requests):
    batchid = trafficdata.save2db()
    data = []
    for d in models.TrafficData.objects.filter(batchid=batchid).defer("cluster"):
        data.append({
            "clusterid" : d.clusterid,
            "servers" : d.servers,
            "start_time" : d.start_time,
            "end_time" : d.end_time,
            "batchid" : d.batchid,
            "requests" : d.requests,
            "total_time" : d.total_time,
            "min_time" : d.min_time,
            "max_time" : d.max_time,
            "avg_time" : d.avg_time,
            "get_remote_sessions" : d.get_remote_sessions,
            "delete_remote_sessions" : d.delete_remote_sessions,
            "status" : d.status,
            "domains" : d.domains
        })

    return JsonResponse({"data":data,"status":200},status=200,encoder=JSONEncoder)

def _model_to_dict(obj):
    result = {}
    for f in obj.__class__._meta.fields:
        o = getattr(obj,f.name)
        if isinstance(o,models.django_models.Model):
            result[f.name] = _model_to_dict(o)
        else:
            result[f.name] = o

    return result


def update_model_4_test(request,name):
    modelcls = getattr(models,name)
    data = json.loads(request.POST.get("data"))
    obj = modelcls.objects.filter(**data["filter"]).first()
    if not obj:
        obj = modelcls(**data["filter"])
    changed = False
    for k,v in data.get("defaults",{}).items():
        if getattr(obj,k) != v:
            setattr(obj,k,v)
            changed = True
    if changed:
        obj.clean()
        obj.save()

    result = _model_to_dict(obj)
    result["_changed"] = changed
            
    return JsonResponse(result,status=200,encoder=JSONFormater)


def del_model_4_test(request,name):
    modelcls = getattr(models,name)
    data = json.loads(request.POST.get("data"))
    result = modelcls.objects.filter(**data).delete()
    return JsonResponse(result,status=200,encoder=JSONFormater,safe=True)

def refresh_modelcache_4_test(request,name):
    modelcls = getattr(models,name)
    #wait cache to refresh
    waitseconds = (modelcls.get_next_refreshtime() - timezone.localtime()).total_seconds()
    if waitseconds > 0:
        time.sleep(waitseconds)
    return views.SUCCEED_RESPONSE


def search_model_4_test(request,name):
    modelcls = getattr(models,name)
    data = json.loads(request.POST.get("data"))
    result = []
    for obj in  modelcls.objects.filter(**data):
        result.append(_model_to_dict(obj))

    return JsonResponse(result,status=200,encoder=JSONFormater,safe=True)


def test_tcontrol(request):
    client = request.GET.get("client")
    clientip = request.GET.get("clientip")
    test = request.GET.get("test","0") == "1"
    tcontrol = cache.tcontrols.get(int(request.GET.get("tcontrol")))
    exempt = True if request.GET.get("exempt") == "1" else False
    if not tcontrol or not tcontrol.active:
        #not traffic control configured
        result = [True,"Tcontrol Not Configured",0]
    else:
        result = views._check_tcontrol(tcontrol,clientip,client,exempt,test=test)
    return JsonResponse(result, safe=False)

def clear_tcontroldata(request):
    tcontrol = cache.tcontrols.get(int(request.GET.get("tcontrol")))

    if not settings.TRAFFICCONTROL_SUPPORTED:
        cahce.clear_tcontroldata(settings.TRAFFICCONTROL_CLUSTERID,tcontrol.id)
    else:
        keypattern = "{}*".format(settings.GET_TRAFFICCONTROL_CACHE_KEY(tcontrol.name))
        for i in range(settings.TRAFFICCONTROL_CACHE_SERVERS):
            if settings.TRAFFICCONTROL_CACHE_SERVERS == 1:
                name = "tcontrol"
            else:
                name = "tcontrol{}".format(i)
            client = caches[name].redis_client
            tcontrolkeys = client.keys(keypattern)
            if tcontrolkeys:
                client.delete(*tcontrolkeys)

    return views.SUCCEED_RESPONSE



def _tcontrol(request):
    clientip = request.headers.get("x-real-ip")

    test = request.GET.get("test","1") == "1"
    domain = request.get_host()
    path = request.headers.get("x-upstream-request-uri")
    if path:
        #get the original request path
        #remove the query string
        try:
            path = path[:path.index("?")]
        except:
            pass
    else:
        #can't get the original path, use request path directly
        path = request.path

    method = request.headers.get("x-upstream-request-method") or "GET"
    if not method:
        method = models.TrafficControlLocation.GET
    else:
        method = models.TrafficControlLocation.METHODS.get(method) or models.TrafficControlLocation.METHODS.get(method.upper()) or models.TrafficControlLocation.GET

    tcontrol = cache.tcontrols.get((domain,path,method))
    if not tcontrol or not tcontrol.active:
        #no traffic control policies are enabled.
        return JsonResponse([True,"_DISABLED_",0], safe=False)
    exempt = False
    if request.user.is_authenticated:
        client = request.user.email
        if tcontrol.is_exempt(client):
            #is the user we known,exempt traffic control
            if (tcontrol.iplimit == 0 or tcontrol.iplimitperiod == 0) and (tcontrol.concurrency == 0 or tcontrol.est_processtime == 0):
                return JsonResponse([True,None,0], safe=False)
            else:
                exempt = True
    else:
        client = request.COOKIES.get(settings.TRAFFICCONTROL_COOKIE_NAME) or None

    if settings.TRAFFICCONTROL_SUPPORTED:
        result = views._check_tcontrol(tcontrol,clientip,client,exempt,test)
    else:
        result = cahce.tcontrol(settings.TRAFFICCONTROL_CLUSTERID,tcontrol.id,clientip,client,exempt,test)
    
    return JsonResponse(result, safe=False)

def test_auth_tcontrol(request):
    res = views.auth(request)
    if res.status_code > 300:
        return res
    #authentication and authorization succeed
    #check the traffic control
    return _tcontrol(request)

def test_auth_optional_tcontrol(request):
    res = views.auth_optional(request)
    if res.status_code > 300:
        return res
    #check the traffic control
    return _tcontrol(request)

def test_auth_basic_tcontrol(request):
    res = views.auth_basic(request)
    if res.status_code > 300:
        return res
    #check the traffic control
    return _tcontrol(request)

def test_auth_basic_optional_tcontrol(request):
    res = views.auth_basic_optional(request)
    if res.status_code > 300:
        return res
    #check the traffic control
    return _tcontrol(request)

