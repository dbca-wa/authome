import time
import logging
import itertools
import traceback
from importlib import import_module

from django.conf import settings
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.exceptions import SessionInterrupted
from django.utils.cache import patch_vary_headers
from django.utils.deprecation import MiddlewareMixin
from django.utils.http import http_date
from django.http import HttpResponse,HttpResponseForbidden
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY
from django.http.cookie import SimpleCookie as DjangoSimpleCookie

from .models import DebugLog
from . import utils

logger = logging.getLogger(__name__)

FORBIDDEN_RESPONSE = HttpResponseForbidden()
LB_HASH_KEY_MISSING_RESPONSE = HttpResponse("Can't find X-lb-hash-key",status=500)

class SimpleCookie(DjangoSimpleCookie):
    """
    Enable add multiple "Set-Cookie" for same cookie but different domain in response to delete a cookie for different domains
    But some browser can delete the cookie from different domains, other browser only choose one 'Set-Cookie' to delete the cookie from only one domain
    So this solution is not reliable.
    """
    def __init__(self,simplecookie=None):
        for k,v, in (simplecookie or {}).items():
            self[k] = v

    def delete_cookie(self, key, path='/', domain=None, samesite=None,secure=False,httponly=False):
        cookies = DjangoSimpleCookie()
        cookies[key] = ""
        c = cookies[key]
        try:
            existing = self[key]
            #already existing, create another cookie with same name
            self["{}({}{})".format(key,domain,path)] = c
        except KeyError as ex:
            #does not exist before, add it directly
            self[key] = c

        c["expires"] ='Thu, 01 Jan 1970 00:00:00 GMT'
        if domain is not None:
            c['domain'] = domain
        
        c['max-age'] = 0
        if path is not None:
            c['path'] = path
        if secure:
            c['secure'] = True
        if samesite:
            c['samesite'] = samesite
        if secure:
            c['secure'] = True
        if httponly:
            c['httponly'] = True
 
def check_integrity(lb_hash_key,auth2_clusterid,signature):
    sig = utils.sign_lb_hash_key(lb_hash_key,auth2_clusterid,settings.SECRET_KEY)
    if signature != sig:
        if settings.PREVIOUS_SECRET_KEY:
            sig = utils.sign_lb_hash_key(hash_key,auth2_clusterid,settings.PREVIOUS_SECRET_KEY)
            if signature != sig:
                return False
        else:
            return False

    return True

class SessionMiddleware(MiddlewareMixin):
    def __init__(self, get_response=None):
        super().__init__(get_response)
        engine = import_module(settings.SESSION_ENGINE)
        self.SessionStore = engine.SessionStore

    def process_request(self, request):
        try:
            session_cookie = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
            
            DebugLog.attach_request(request)
            if session_cookie:
                values = session_cookie.rsplit(settings.SESSION_COOKIE_DOMAIN_SEPATATOR,1)
                if len(values) == 1:
                    cookie_domain = None
                    values = values[0]
                else:
                    values,cookie_domain = values
    
                #if session_key is a cluster session key, extract the session_key from cluster session key
                try:
                    session_key = values[values.rindex("|") + 1:]
                    cookie_changed = True
                except:
                    session_key = values
                    cookie_changed = False
    
    
                if self.SessionStore.is_cookie_domain_match(request,cookie_domain):
                    request.session = self.SessionStore(session_key=session_key,request=request,cookie_domain=cookie_domain)
                else:
                    request.session = self.SessionStore(session_key=None,request=request,cookie_domain=cookie_domain)
                    logger.warning("The domain({1}) of the cookie({0}) does not match the required domain({2})".format(session_cookie,cookie_domain,self.SessionStore.get_cookie_domain(request)))
                    DebugLog.log(DebugLog.DOMAIN_NOT_MATCH,None,None,session_key,session_key,message="The domain({1}) of the session cookie({0}) does not match the required domain({2}),request={3},cookies={4}".format(session_cookie,cookie_domain,self.SessionStore.get_cookie_domain(request),request.path_info,request.headers.get("cookie")))
                if cookie_changed:
                    request.session._cookie_changed = True
    
            else:
                request.session = self.SessionStore(session_key=None,request=request)
        except Exception as ex: 
            DebugLog.log(DebugLog.ERROR,utils.get_source_lb_hash_key(request),utils.get_source_clusterid(request),utils.get_source_session_key(request),utils.get_source_session_cookie(request),message="Failed to process request . request={}, cookies={}. {}".format("{}{}".format(utils.get_host(request),request.path_info),request.headers.get("cookie"),str(ex)))
            raise ex

    def process_response(self, request, response):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie or delete
        the session cookie if the session has been emptied.
        """
        try:
            try:
                accessed = request.session.accessed
                modified = request.session.modified
                empty = request.session.is_empty()
            except AttributeError:
                return response
            # First check if we need to delete this cookie.
            # The session should be deleted only if the session is entirely empty.
            if empty:
                if settings.SESSION_COOKIE_NAME in request.COOKIES:
                    response.delete_cookie(
                        settings.SESSION_COOKIE_NAME,
                        path=settings.SESSION_COOKIE_PATH,
                        domain=request.session.current_cookie_domain,
                        samesite=settings.SESSION_COOKIE_SAMESITE
                    )
                    patch_vary_headers(response, ('Cookie',))
                    DebugLog.log_if_true("-" in utils.get_source_session_key(request) ,DebugLog.DELETE_COOKIE,DebugLog.get_lb_hash_key(request.session),utils.get_source_clusterid(request),utils.get_source_session_key(request),utils.get_source_session_cookie(request),message="Delete an expired authenticated session cookie({})".format(utils.get_source_session_cookie(request)))
            else:
                if accessed:
                    patch_vary_headers(response, ('Cookie',))
    
                if response.status_code != 500 and (modified or settings.SESSION_SAVE_EVERY_REQUEST):
                    try:
                        request.session.save()
                    except UpdateError:
                        raise SessionInterrupted(
                            "The request's session was deleted before the "
                            "request completed. The user may have logged "
                            "out in a concurrent request, for example."
                        )
    
                if request.session.cookie_changed:
                    logger.debug("Return a session cookie '{}...' in response".format(request.session.cookie_value[:-10]))
                    if request.session.get_expire_at_browser_close():
                        max_age = None
                        expires = None
                    else:
                        max_age = request.session.get_expiry_age()
                        expires_time = time.time() + max_age
                        expires = http_date(expires_time)
    
                    response.set_cookie(
                        settings.SESSION_COOKIE_NAME,
                        request.session.cookie_value, 
                        max_age=max_age,
                        expires=expires, 
                        domain=request.session.cookie_domain,
                        path=settings.SESSION_COOKIE_PATH,
                        secure=settings.SESSION_COOKIE_SECURE or None,
                        httponly=settings.SESSION_COOKIE_HTTPONLY or None,
                        samesite=settings.SESSION_COOKIE_SAMESITE
                    )
                    #Only record authenticated session
                    DebugLog.log_if_true("-" in (request.session.session_key or request.session.expired_session_key) and utils.get_source_session_key(request) == (request.session.session_key or request.session.expired_session_key),DebugLog.UPDATE_COOKIE,DebugLog.get_lb_hash_key(request.session),utils.get_source_clusterid(request),request.session.session_key,utils.get_source_session_cookie(request),message="Return an updated session cookie({})".format(request.session.cookie_value),userid=request.session.get(USER_SESSION_KEY),target_session_cookie=request.session.cookie_value)
                        
                    DebugLog.log_if_true("-" in (request.session.session_key or request.session.expired_session_key) and utils.get_source_session_key(request) != (request.session.session_key or request.session.expired_session_key),DebugLog.CREATE_COOKIE,DebugLog.get_lb_hash_key(request.session),utils.get_source_clusterid(request),request.session.session_key,utils.get_source_session_cookie(request),message="Return a new session cookie({})".format(request.session.cookie_value),userid=request.session.get(USER_SESSION_KEY),target_session_cookie=request.session.cookie_value)
            return response
        except Exception as ex: 
            DebugLog.log(DebugLog.ERROR,utils.get_source_lb_hash_key(request),utils.get_source_clusterid(request),utils.get_source_session_key(request),utils.get_source_session_cookie(request),message="Failed to process request . request={}, cookies={}. {}".format("{}{}".format(utils.get_host(request),request.path_info),request.headers.get("cookie"),str(ex)))
            raise ex


class ClusterSessionMiddleware(SessionMiddleware):
    def process_request(self, request):
        try:
            session_cookie = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
            nginx_lb_hash_key = request.headers.get("X-lb-hash-key")
            if not nginx_lb_hash_key and not request.path.startswith("/cluster"):
                return LB_HASH_KEY_MISSING_RESPONSE
            DebugLog.attach_request(request)
            cookie_domain = None
            if session_cookie:
                values = session_cookie.split("|",3)
                length = len(values)
                if length == 1:
                    values = session_cookie.rsplit(settings.SESSION_COOKIE_DOMAIN_SEPATATOR,1)
                    if len(values) == 1:
                        cookie_domain = None
                        session_key = values[0]
                    else:
                        session_key,cookie_domain = values
    
                    if self.SessionStore.is_cookie_domain_match(request,cookie_domain) :
                        request.session = self.SessionStore(nginx_lb_hash_key,None,session_key,request=request,cookie_domain=cookie_domain)
                    else:
                        request.session = self.SessionStore(nginx_lb_hash_key,None,None,request=request,cookie_domain=cookie_domain)
                        logger.warning("The domain({1}) of the session cookie({0}) does not match the required domain({2}),request={3},cookies={4}".format(session_cookie,cookie_domain,self.SessionStore.get_cookie_domain(request),request.path_info,request.headers.get("cookie")))
                        DebugLog.log(DebugLog.DOMAIN_NOT_MATCH,nginx_lb_hash_key,None,session_key,session_cookie,message="The domain({1}) of the session cookie({0}) does not match the required domain({2}),request={3},cookies={4}".format(session_cookie,cookie_domain,self.SessionStore.get_cookie_domain(request),request.path_info,request.headers.get("cookie")))
                elif length == 4:
                    try:
                        lb_hash_key,auth2_clusterid,signature,session_key = values
                        values = session_key.rsplit(settings.SESSION_COOKIE_DOMAIN_SEPATATOR,1)
                        if len(values) == 1:
                            cookie_domain = None
                            session_key = values[0]
                        else:
                            session_key,cookie_domain = values
                        #some browser has a bug "send multiple values for a single cookie", or send a cookie for different domain
                        if not self.SessionStore.is_cookie_domain_match(request,cookie_domain):
                            #load balance hash key does not match the lb hash key in session cookie, or cookie domain does not match the required domain
                            #this is a abnormal scenario, logout and let user login again
                            request.session = self.SessionStore(nginx_lb_hash_key,None,None,request=request,cookie_domain=cookie_domain)
                            logger.warning("The domain({1}) of the session cookie({0}) does not match the required domain({2}) . request={3}, cookies={4}".format(session_cookie,cookie_domain,self.SessionStore.get_cookie_domain(request),"{}{}".format(utils.get_host(request),request.path_info),request.headers.get("cookie")))
                            DebugLog.log(DebugLog.DOMAIN_NOT_MATCH,nginx_lb_hash_key,auth2_clusterid,session_key,session_cookie,message="The domain({1}) of the session cookie({0}) does not match the required domain({2}) . request={3}, cookies={4}".format(session_cookie,cookie_domain,self.SessionStore.get_cookie_domain(request),"{}{}".format(utils.get_host(request),request.path_info),request.headers.get("cookie")))
                            return
                        elif nginx_lb_hash_key != lb_hash_key:
                            #load balance hash key does not match the lb hash key in session cookie, or cookie domain does not match the required domain
                            #this is a abnormal scenario, logout and let user login again
                            request.session = self.SessionStore(nginx_lb_hash_key,None,None,request=request,cookie_domain=cookie_domain)
                            logger.warning("The lb hash key({}) in session cookie({}) does not match the request header 'lb-hash-key'({}),maybe more than one session cookies were sent . request={}, cookies={}".format(lb_hash_key,session_cookie,nginx_lb_hash_key,"{}{}".format(utils.get_host(request),request.path_info),request.headers.get("cookie")))
                            DebugLog.log(DebugLog.LB_HASH_KEY_NOT_MATCH,nginx_lb_hash_key,auth2_clusterid,session_key,session_cookie,message="The lb hash key({}) in session cookie({}) does not match the request header 'lb-hash-key'({}),maybe more than one session cookies were sent . request={}, cookies={}".format(lb_hash_key,session_cookie,nginx_lb_hash_key,"{}{}".format(utils.get_host(request),request.path_info),request.headers.get("cookie")))
                            return
                        
                        if auth2_clusterid != settings.AUTH2_CLUSTERID:
                            #current auth2 server is not the original auth2 server
                            #maybe caused by new auth2 server added, existing auth2 server removed, some auth2 server unavailable, or hacked by the user
                            if not check_integrity(lb_hash_key,auth2_clusterid,signature):
                                #session cookie is hacked by the user or 
                                DebugLog.log(DebugLog.SESSION_COOKIE_HACKED,nginx_lb_hash_key,auth2_clusterid,session_key,session_cookie,message="The hash  key of the session cookie({0}) does not match the required hash key.".format(session_cookie))
                                return FORBIDDEN_RESPONSE
    
                        request.session = self.SessionStore(lb_hash_key,auth2_clusterid,session_key,request=request,cookie_domain=cookie_domain)
                    except:
                        #invalid session cookie
                        request.session = self.SessionStore(nginx_lb_hash_key,None,None,request=request,cookie_domain=cookie_domain)
                        return
                else:
                    if settings.SESSION_COOKIE_DOMAIN_SEPATATOR in session_cookie:
                        cookie_domain = session_cookie.rsplit(settings.SESSION_COOKIE_DOMAIN_SEPATATOR,1)[-1]
                    else:
                        cookie_domain = None
                    #invalid session key
                    request.session = self.SessionStore(nginx_lb_hash_key,None,None,request=request,cookie_domain=cookie_domain)
                    return
            else:
                request.session = self.SessionStore(nginx_lb_hash_key,settings.AUTH2_CLUSTERID,None,request=request)
        except Exception as ex: 
            DebugLog.log(DebugLog.ERROR,utils.get_source_lb_hash_key(request),utils.get_source_clusterid(request),utils.get_source_session_key(request),utils.get_source_session_cookie(request),message="Failed to process request . request={}, cookies={}. {}".format("{}{}".format(utils.get_host(request),request.path_info),request.headers.get("cookie"),str(ex)))
            raise ex

