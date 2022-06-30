import logging
from datetime import datetime

from django.conf import settings
from django.utils import timezone
from django.http import JsonResponse, HttpResponse

from .views import SUCCEED_RESPONSE,RESPONSE_NOT_FOUND
from ..cache import cache,get_defaultcache,get_usercache
from ..sessionstore import SessionStore
from .. import models

logger = logging.getLogger(__name__)

defaultcache = get_defaultcache()

#pre creaed authentication not required response used by auth_optional,status = 204
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
    return SUCCEED_RESPONSE

def user_changed(request,userid):
    usercache = get_usercache(userid)
    if usercache:
        try:
            usercache.delete(settings.GET_USER_KEY(userid))
        except Exception as ex:
            logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))

    return SUCCEED_RESPONSE

def usertoken_changed(request,userid):
    usercache = get_usercache(userid)
    if usercache:
        try:
            usercache.delete(settings.GET_USERTOKEN_KEY(userid))
        except Exception as ex:
            logger.error("Failed to delete the token of the user({}) from user cache.{}".format(userid,str(ex)))

    return SUCCEED_RESPONSE

def users_changed(request):
    userids=request.POST.get("users")
    if not userids:
        return SUCCEED_RESPONSE
    for i in userids.split(","):
        try:
            userid = int(i)
            usercache = get_usercache(userid)
            if usercache:
                usercache.delete(settings.GET_USER_KEY(userid))
        except Exception as ex:
            logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))

    return SUCCEED_RESPONSE

def usertokens_changed(request):
    userids=request.POST.get("users")
    if not userids:
        return SUCCEED_RESPONSE
    for i in userids.split(","):
        try:
            userid = int(i)
            usercache = get_usercache(userid)
            if usercache:
                usercache.delete(settings.GET_USERTOKEN_KEY(userid))
        except Exception as ex:
            logger.error("Failed to delete the token of the user({}) from user cache.{}".format(userid,str(ex)))

    return SUCCEED_RESPONSE

def get_remote_session(request):
    sessionstore = SessionStore(session_key=request.POST.get("session"),auth2_clusterid=settings.AUTH2_CLUSTERID)
    session_data = sessionstore.load()
    if session_data:
        timeout = session_data.get("session_timeout")
        if not timeout or not session_data.get(USER_SESSION_KEY):
            ttl = sessionstore.ttl
        else:
            ttl = None
        if ttl:
            return JsonResponse({"session":session_data,"ttl":ttl},status=200)
        else:
            return JsonResponse({"session":session_data},status=200)
    else:
        return RESPONSE_NOT_FOUND



