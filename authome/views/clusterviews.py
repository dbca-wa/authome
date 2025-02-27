import logging
from datetime import datetime

from django.conf import settings
from django.utils import timezone
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY

from ..cache import cache,get_defaultcache,get_usercache
from ..sessionstore import SessionStore,StandaloneSessionStore
from .. import models
from . import views
from .. import utils
from ..serializers import JSONEncoder

logger = logging.getLogger(__name__)

defaultcache = get_defaultcache()

#pre created authentication not required response used by auth_optional and auth_basic_optional,status = 204
NO_CHANGE_RESPONSE = HttpResponse(content="Already up to date",status=208)

def config_changed(request,modelname):
    model_cls = getattr(models,modelname)
    modified = request.GET.get("modified")
    model_change_cls = model_cls.get_model_change_cls()
    if modified:
        try:
            modified = timezone.localtime(timezone.make_aware(datetime.strptime(modified,"%Y-%m-%d %H:%M:%S.%f")))
            last_refreshed = defaultcache.get(model_change_cls.key)
            if last_refreshed and last_refreshed > modified:
                #cache is already up to date
                return NO_CHANGE_RESPONSE
        except:
            pass

    model_change_cls.change(localonly=True)
    return HttpResponse(content='Succeed',status=200)

def user_changed(request,userid):
    usercache = get_usercache(userid)
    if usercache:
        try:
            usercache.delete(settings.GET_USER_KEY(userid))
        except Exception as ex:
            logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))

    return HttpResponse(content='Succeed',status=200)

def usertoken_changed(request,userid):
    usercache = get_usercache(userid)
    if usercache:
        try:
            usercache.delete(settings.GET_USERTOKEN_KEY(userid))
        except Exception as ex:
            logger.error("Failed to delete the token of the user({}) from user cache.{}".format(userid,str(ex)))

    return HttpResponse(content='Succeed',status=200)

def users_changed(request):
    userids=request.POST.get("users")
    if not userids:
        return HttpResponse(content='Succeed',status=200)
    for i in userids.split(","):
        try:
            userid = int(i)
            usercache = get_usercache(userid)
            if usercache:
                usercache.delete(settings.GET_USER_KEY(userid))
        except Exception as ex:
            logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))

    return HttpResponse(content='Succeed',status=200)

def usertokens_changed(request):
    userids=request.POST.get("users")
    if not userids:
        return HttpResponse(content='Succeed',status=200)
    for i in userids.split(","):
        try:
            userid = int(i)
            usercache = get_usercache(userid)
            if usercache:
                usercache.delete(settings.GET_USERTOKEN_KEY(userid))
        except Exception as ex:
            logger.error("Failed to delete the token of the user({}) from user cache.{}".format(userid,str(ex)))

    return HttpResponse(content='Succeed',status=200)

def get_remote_session(request):
    session = request.POST.get("session")
    if not session:
        return views.response_not_found_factory(request)

    clusterid = request.POST.get("clusterid")
    if clusterid and clusterid != settings.AUTH2_CLUSTERID:
        return views.response_not_found_factory(request)

    if clusterid:
        #load cluster session from cache
        sessionstore = SessionStore(None,clusterid,session)
    else:
        #load standalone session from cache
        sessionstore = StandaloneSessionStore(session)

    session_data = sessionstore.load()
    logger.debug("Load remote {3} session({1}={2}) from cluster server({0})".format(settings.AUTH2_CLUSTERID,session,session_data,"cluster" if clusterid else "standalone"))
    if session_data:
        timeout = session_data.get("session_timeout")
        if not timeout or not session_data.get(USER_SESSION_KEY):
            ttl = sessionstore.ttl
        else:
            ttl = None
        if ttl:
            return JsonResponse({"session":session_data,"ttl":ttl},status=200,encoder=JSONEncoder)
        else:
            return JsonResponse({"session":session_data},status=200,encoder=JSONEncoder)
    else:
        return views.response_not_found_factory(request)

def delete_remote_session(request):
    session = request.POST.get("session")
    if not session:
        return HttpResponse(content='Succeed',status=200)

    clusterid = request.POST.get("clusterid")
    if clusterid and clusterid != settings.AUTH2_CLUSTERID:
        return HttpResponse(content='Succeed',status=200)

    if clusterid:
        #load cluster session from cache
        sessionstore = SessionStore(None,clusterid,session)
    else:
        #load standalone session from cache
        sessionstore = StandaloneSessionStore(session)

    #remote response cache
    cache.del_auth(None,session)

    sessionstore.delete()
    return HttpResponse(content='Succeed',status=200)

def model_cachestatus(request):
    cache.refresh_auth2_clusters()
    content = {}
    for cls in (models.UserGroup,models.UserGroupAuthorization,models.CustomizableUserflow,models.IdentityProvider):
        cls.refresh_cache_if_required()
        status,refreshtime = cls.cache_status()
        content[cls.__name__] = [status,utils.format_datetime(refreshtime),utils.format_datetime(cls.get_next_refreshtime())]

    return JsonResponse(content,status=200)


def tcontrol(request):
    client = request.GET.get("client")
    clientip = request.GET.get("clientip")
    tcontrol = cache.tcontrols.get(int(request.GET.get("tcontrol")))
    if not tcontrol or not tcontrol.active:
        #not traffic control configured
        return views.SUCCEED_RESPONSE
    if views._check_tcontrol(tcontrol,clientip,client):
        return views.SUCCEED_RESPONSE
    else:
        return views.FORBIDDEN_RESPONSE

