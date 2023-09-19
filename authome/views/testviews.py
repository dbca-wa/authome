import re
import logging
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
from ..serializers import JSONEncoder
from .. import trafficdata
from ..cache import cache

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
    user,created = models.User.objects.update_or_create(email=email,username=email,defaults={"is_staff":is_staff,"last_idp":idp,"last_login":timezone.localtime(),"first_name":firstname,"last_name":lastname})

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
    request.session["session_timeout"] = 3600

    return views.profile(request)

def echo(request):
    data = OrderedDict()
    data["url"] = "https://{}{}".format(request.get_host(),request.get_full_path())
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
            return JsonResponse(session_data,status=200)
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

    


