from datetime import timedelta
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseForbidden, JsonResponse, HttpResponseNotAllowed, HttpResponseNotFound
from django.template.response import TemplateResponse
from django.contrib.auth import logout
from django.urls import reverse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.http import urlencode
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.template import engines
from django.utils.crypto import get_random_string
from django.contrib.auth import login
from django.utils.http import http_date
from django.utils.html import mark_safe

from social_django.utils import psa
from social_core.actions import do_auth, do_complete
from social_core.exceptions import AuthException

from importlib import import_module
from ipware.ip import get_client_ip
import json
import base64
import re
import traceback
import logging
import urllib.parse
import string
from pyotp.totp import TOTP
import time

from .. import models
from .. cache import cache, get_defaultcache
from .. import utils
from .. import emails
from ..exceptions import HttpResponseException,UserDoesNotExistException,PolicyNotConfiguredException
from ..patch import load_user,anonymoususer,load_usertoken
from ..sessionstore import SessionStore
from ..models import DebugLog

from .. import performance

defaultcache = get_defaultcache()

logger = logging.getLogger(__name__)

django_engine = engines['django']

MFA_METHOD_MAPPING = {
    "totp" : "Authenticator App",
    "phone" : "Phone",
    "email" : "Email",
}

RESPONSE_NOT_FOUND = HttpResponseNotFound()
def response_not_found_factory(request):
    if request.session.cookie_changed or request.session.is_empty():
        return HttpResponseNotFound()
    else:
        return RESPONSE_NOT_FOUND

SUCCEED_RESPONSE = HttpResponse(content='Succeed',status=200)
def succeed_response_factory(request):
    if request.session.cookie_changed or request.session.is_empty():
        return HttpResponse(content='Succeed',status=200)
    else:
        return SUCCEED_RESPONSE

FORBIDDEN_RESPONSE = HttpResponseForbidden()
def forbidden_response_factory(request):
    if request.session.cookie_changed or request.session.is_empty():
        return HttpResponseForbidden()
    else:
        return FORBIDDEN_RESPONSE


#creae authentication required response, status=401
AUTH_REQUIRED_RESPONSE = HttpResponse(status=401)
AUTH_REQUIRED_RESPONSE.content = "Authentication required"
def auth_required_response_factory(request):
    if request.session.cookie_changed or request.session.is_empty():
        res = HttpResponse(status=401)
        res.content = "Authentication required"
        return res
    else:
        return AUTH_REQUIRED_RESPONSE

AUTH_NOT_REQUIRED_RESPONSE = HttpResponse(content="Succeed",status=204)
def auth_not_required_response_factory(request):
    if request.session.cookie_changed or request.session.is_empty():
        return HttpResponse(content="Succeed",status=204)
    else:
        return AUTH_NOT_REQUIRED_RESPONSE

#create basic auth required response,status = 401
BASIC_AUTH_REQUIRED_RESPONSE = HttpResponse(status=401)
BASIC_AUTH_REQUIRED_RESPONSE["WWW-Authenticate"] = 'Basic realm="Please login with your email address and access token"'
BASIC_AUTH_REQUIRED_RESPONSE.content = "Basic auth required"
def basic_auth_required_response_factory(request):
    if request.session.cookie_changed or request.session.is_empty():
        res = HttpResponse(status=401)
        res["WWW-Authenticate"] = 'Basic realm="Please login with your email address and access token"'
        res.content = "Basic auth required"
        return res
    else:
        return BASIC_AUTH_REQUIRED_RESPONSE
    return res

encode_url_parameters = lambda parameters,selected_params=None:"&".join("{}={}".format(k,urllib.parse.quote(v) if isinstance(v,str) else v) for k,v in parameters.items() if not selected_params or k in selected_params) if parameters else None
def _get_next_url(request):
    """
    Get the non-null absolute next url .
    1. If request has parameter 'next', use the value of parameter 'next' as next url, then go to step 5
    2. if request has header 'x-upstream-request-uri', use request's host and the value of the header 'x-upstream-request-uri' to populate next url, then go to step  5
    3. if session has proeprty 'next', use the value of the session property 'next' as next url. then go to step 5
    4. use request host and url '/sso/setting' to populate next url
    5. get the domain from next url, if failed, use request host, and then use this domain to build a absoulute next  url
    """
    next_url = request.GET.get(REDIRECT_FIELD_NAME)
    #try to get next url from request
    if not next_url and request.headers.get("x-upstream-request-uri"):
        next_url = "https://{}{}".format(request.get_host(),request.headers.get("x-upstream-request-uri"))

    if not next_url:
        #get next url from session
        next_url = request.session.get(REDIRECT_FIELD_NAME)

    if next_url:
        #found next url, build its absolute url
        domain = utils.get_domain(next_url)
        if not domain:
            domain = request.get_host()
        next_url = get_absolute_url(next_url,domain)
        logger.debug("Found next url '{}'".format(next_url))
    else:
        #next url is not found, use default next url
        domain = request.get_host()
        if domain == settings.AUTH2_DOMAIN:
            next_url = "https://{}/sso/setting".format(domain)
        else:
            next_url = "https://{}".format(domain)

        logger.debug("No next url provided,set the next url to '{}'".format(next_url))

    return next_url


basic_auth_re = re.compile('^Basic\s+([a-zA-Z0-9+/=]+)$')
def _parse_basic(basic_auth):
    """
    Parse the basic header to a tuple(username,password)
    Throw excepton if can't find the basic auth data
    """
    if not basic_auth:
        raise Exception('Missing user credential')
    match = basic_auth_re.match(basic_auth)
    if not match:
        raise Exception('Malformed Authorization header')
    basic_auth_raw = base64.b64decode(match.group(1)).decode('utf-8')
    if ':' not in basic_auth_raw:
        raise Exception('Missing password')
    return basic_auth_raw.split(":", 1)

def check_authorization(request,useremail,domain=None,path=None):
    """
    Check whether the user(identified by email) has the permission to access the resource
    Return None if authorized;otherwise return forbidden response
    """
    #get the real request domain and request path from request header set in nginx if have;otherwise use the domain and path from http request
    if not domain:
        domain = request.get_host()
    if not path:
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


    if path.startswith("/sso/"):
        logger.debug("All paths startswith '/sso' are accessible for everyone by default.")
        return None
    elif models.can_access(useremail,domain,path):
        logger.debug("User({}) can access https://{}{}".format(useremail,domain,path))
        return None
    else:
        logger.debug("User({}) can't access https://{}{}".format(useremail,domain,path))
        return forbidden_response_factory(request)

def get_absolute_url(url,domain):
    """
    Get a absolute http url
    """
    if url.startswith("http"):
        #url is already an absolute url
        return url

    if url.startswith("/"):
        #relative url in domain
        return "https://{}{}".format(domain,url)
    else:
        #absoulte url without protocol
        return "https://{}".format(url)

def get_post_b2c_logout_url(request,encode=True):
    """
    Get post b2c logout url which will be redirect to by dbcab2c after log out from dbca b2c.
    The logout url is based on idp's logout method.
        1. idp without logout url: logout url is /sso/signedout
        2. idp with automatically logout method: logout url is the idp's logout url
        3. idp with automatically logout method via popup window: logout url is /sso/signedout, but returned page will open a browser window to logout from idp and then close the window automatically
        4. idp with logout url: logout url is /ssp/signedout, but the returned page will show a hyperlink to let user logout from  idp
    if the logout url is /sso/signedout,it can have url parameters.
        relogin_url: the url to relogin
        idp: the idpid of the IdentiryProvider which is used for login
    params:
        request: the current http request
        idp: the currently used IdentiryProvider if have
        encode: encode the url if True;
    Return 	quoted post logout url
    """
    host = request.GET.get("domain") or request.get_host()

    message = request.GET.get("message")
    #get the idp and idepid
    idpid = None
    idp = None
    idppk = request.GET.get("idp")
    if idppk:
        idp = models.IdentityProvider.get_idp(int(idppk))
        if idp:
            idpid = idp.idp
    else:
        #get idp from session
        idpid = request.session.idpid
        if idpid:
            idp = models.IdentityProvider.get_idp(idpid)
            if not idp:
                #can't find the IdentityProvider with idpid,reset idpid to None
                idpid = None
            else:
                idppk = idp.id

    next_url = request.GET.get("next")
    relogin_url = None
    if next_url:
        domain,next_url= utils.get_domain_path(next_url)
        domain = domain or host
        next_url = next_url or "/"
    else:
        relogin_url = request.GET.get("relogin")
        if relogin_url:
            domain,relogin_url= utils.get_domain_path(relogin_url)
            domain = domain or host
        else:
            domain = host

    params = {}
    userflow_signout =  _get_userflow_signout(request,domain)
    if userflow_signout.signedout_url:
        signedout_url = userflow_signout.signedout_url
    else:
        signedout_url = "/sso/signedout"

    if next_url:
        params["relogin"] = next_url
    elif userflow_signout.relogin_url:
        params["relogin"] = userflow_signout.relogin_url
    elif relogin_url:
        params["relogin"] = relogin_url
    elif domain == settings.AUTH2_DOMAIN:
        params["relogin"] = "/sso/setting"
    else:
        params["relogin"] = "/"

    if message:
        params["message"] = message


    #get the absolute signedout url
    if idp and idp.logout_url:
        if idp.logout_method == models.IdentityProvider.AUTO_LOGOUT_WITH_POPUP_WINDOW:
            params["idp"] = idp.name or idp.idp
            params["idplogout"] = idp.logout_url
            params["signedout"] = signedout_url

            post_b2c_logout_url = "https://{}/sso/signout_socialmedia?{}".format(domain,encode_url_parameters(params))
        elif idp.logout_method == models.IdentityProvider.AUTO_LOGOUT:
            if params:
                post_b2c_logout_url = "https://{}{}?{}".format(domain,signedout_url,encode_url_parameters(params))
            else:
                post_b2c_logout_url = "https://{}{}".format(domain,signedout_url)

            post_b2c_logout_url = idp.logout_url.format(urllib.parse.quote(post_b2c_logout_url))
        else:
            params["idp"] = idp.name or idp.idp
            params["idplogout"] = idp.logout_url
            post_b2c_logout_url = "https://{}{}?{}".format(domain,signedout_url,encode_url_parameters(params))
    else:
        if params:
            post_b2c_logout_url = "https://{}{}?{}".format(domain,signedout_url,encode_url_parameters(params))
        else:
            post_b2c_logout_url = "https://{}{}".format(domain,signedout_url)

    #return econded or non-encoded post_b2c_logout_url based on parameter 'encode'
    return urllib.parse.quote(post_b2c_logout_url) if encode else post_b2c_logout_url

def _populate_response(request,f_cache,cache_key,user,session_key=None):
    """
    Populate authenticated and authorized response,  and then cache it.
    Return the populated response,
    """
    #populate the response header data
    headers = {
        'email': user.email,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'full_name' : "{} {}".format(user.first_name,user.last_name),
        'groups': models.UserGroup.find_groups(user.email)[1],
        'logout_url' : "/sso/auth_logout"
    }
    if session_key:
        headers['session_key'] = session_key

    #populate the response and cached reponse.
    response = HttpResponse(content="Succeed")
    cached_response = HttpResponse(content="Succeed")
    for key, val in headers.items():
        key = "X-" + key.replace("_", "-")
        response[key] = val
        cached_response[key] = val

    cached_response["X-auth-cache-hit"] = "success"
    response["remote-user"] = user.email
    cached_response["remote-user"] = user.email
    # cache the response
    f_cache(user,cache_key,cached_response)
    logger.debug("cache the sso auth data for the user({}) with key({})".format(user.email,cache_key))

    return response

def _auth(request):
    """
    Authenticate and authorization the request;
    Return
        None: not authenticated
        200 Response: authenticated and authorized
        403 Response: authenticated but not authorized.
    """
    try:
        performance.start_processingstep("auth")
        performance.start_processingstep("authentication")
        try:
            if not request.user.is_authenticated or not request.user.is_active:
                #not authenticated or user is inactive
                return None
        finally:
            performance.end_processingstep("authentication")
            pass


        performance.start_processingstep("authorization")
        try:
            #authenticated
            #check authorization
            res = check_authorization(request,request.user.email)
            if res:
                #not authorized
                return res
        finally:
            performance.end_processingstep("authorization")
            pass


        performance.start_processingstep("create_response")
        try:
            #authorized
            #get the reponse from cache
            user = request.user
            auth_key = request.session.session_key
            response = None if (request.session.cookie_changed or request.session.is_empty()) else cache.get_auth(user,auth_key,user.modified)

            if response and models.UserGroup.find_groups(user.email)[1] == response["X-groups"]:
                #response cached
                return response
            else:
                #reponse not cached or outdated, populate one and cache it.
                return _populate_response(request,cache.set_auth,auth_key,user,request.session.cookie_value)
        finally:
            performance.end_processingstep("create_response")
            pass

    finally:
        performance.end_processingstep("auth")
        pass

@csrf_exempt
def auth(request):
    """
    view method for path '/sso/auth'
    Return
        200 reponse: authenticated and authorized
        401 response: not authenticated
        403 reponse: authenticated,but not authorized
    """
    request.session.modified = False
    res = _auth(request)
    if res:
        #authenticated, but can be authorized or not authorized
        return res
    else:
        #not authenticated
        return auth_required_response_factory(request)

@csrf_exempt
def auth_optional(request):
    """
    view method for path '/sso/auth_optional'
    Return
        200 reponse: authenticated and authorized
        204 response: not authenticated
        403 reponse: authenticated,but not authorized
    """
    request.session.modified = False

    try:
        performance.start_processingstep("auth")
        performance.start_processingstep("authentication")
        try:
            if not request.user.is_authenticated or not request.user.is_active:
                #not authenticated or user is inactive
                return auth_not_required_response_factory(request)
        finally:
            performance.end_processingstep("authentication")
            pass

        performance.start_processingstep("create_response")
        try:
            #get the reponse from cache
            user = request.user
            auth_key = request.session.session_key
            response = None if (request.session.cookie_changed or request.session.is_empty()) else cache.get_auth(user,auth_key,user.modified)

            if response and models.UserGroup.find_groups(user.email)[1] == response["X-groups"]:
                #response cached
                return response
            else:
                #reponse not cached or outdated, populate one and cache it.
                return _populate_response(request,cache.set_auth,auth_key,user,request.session.cookie_value)
        finally:
            performance.end_processingstep("create_response")
            pass

    finally:
        performance.end_processingstep("auth")
        pass

def is_usertoken_valid(user,token):
    """
    check whether the user token is valid or not
    """
    usertoken = load_usertoken(user)
    return usertoken and usertoken.is_valid(token)

@csrf_exempt
def auth_basic(request):
    """
    view method for path '/sso/auth_basic'
    First authenticate with useremail and user token; if failed,fall back to session authentication
    """
    #get the basic auth header
    auth_basic = request.META.get('HTTP_AUTHORIZATION').strip() if 'HTTP_AUTHORIZATION' in request.META else None
    if not auth_basic:
        #basic auth data not found
        #check whether session is already authenticated or not.
        res = _auth(request)
        if res:
            #already authenticated
            return res
        else:
            #not authenticated, return basic auth required response
            return basic_auth_required_response_factory(request)

    #get the user name and user toke by parsing the basic auth data
    try:
        useremail, token = _parse_basic(auth_basic)
    except:
        #failed to parse the basic auth data from request
        #fallback to normal authentication session
        res = _auth(request)
        if res:
            #already authenticated
            return res
        else:
            #not authenticated, return basic auth required response
            return basic_auth_required_response_factory(request)

    #try to get the reponse from cache with useremail and token
    auth_basic_key = cache.get_basic_auth_key(useremail,token)
    userid,response = cache.get_basic_auth(auth_basic_key)

    if response:
        #found the cached reponse, already authenticated
        useremail = response['X-email']
        try:
            if settings.CHECK_AUTH_BASIC_PER_REQUEST:
                #check whehter user token is valid or not
                #get the user object via useremail
                user = load_user(userid)
                if user == anonymoususer or user.email != useremail:
                    raise Exception("User was changed, check again.")

                if not user.is_active :
                    logger.debug("The user({}) is inactive.".format(useremail))
                    cache.delete_basic_auth(auth_basic_key)
                    return basic_auth_required_response_factory(request)
                elif not is_usertoken_valid(user,token):
                    #token is invalid, remove the cached response
                    cache.delete_basic_auth(auth_basic_key)
                    #fallback to session authentication
                    res = _auth(request)
                    if res:
                        #already authenticated, but can be authorized or not authorized
                        logger.debug("Failed to authenticate the user({}) with token, fall back to use session authentication".format(useremail))
                        return res
                    else:
                        #not authenticated, return basic auth required reponse
                        logger.debug("Failed to authenticate the user({}) with token".format(useremail))
                        return basic_auth_required_response_factory(request)

            request.session.modified = False
            #check authorization
            res = check_authorization(request,useremail)
            if res:
                #not authorized
                return res
            else:
                #authorized
                return response
        except:
            cache.delete_basic_auth(auth_basic_key)

    #not found the cached reponse, not authenticated before.
    try:
        performance.start_processingstep("fetch_user_with_email_from_db")
        try:
            user = models.User.objects.get(email__iexact=useremail)
        finally:
            performance.end_processingstep("fetch_user_with_email_from_db")
            pass

        if request.user.is_authenticated and user.email == request.user.email:
            #the user of the token auth is the same user as the authenticated session user;use the session authentication data directly
            return  _auth(request)

        #user session is not authenticated or the user of the user token is not the same user as the authenticated sesion user.
        #check whther user token is valid
        if user.is_active and is_usertoken_valid(user,token):
            #user token is valid, authenticated
            logger.debug("Succeed to authenticate the user({}) with token".format(useremail))
            request.user = user
            request.session.modified = False
            #populate and cache the authenticated basic auth response
            response = _populate_response(request,cache.set_basic_auth,auth_basic_key,user)
            #check authorization
            res = check_authorization(request,user.email)
            if res:
                #not authorized
                return res
            else:
                #authorized
                return response
        elif not user.is_active :
            logger.debug("The user({}) is inactive.".format(useremail))
            return basic_auth_required_response_factory(request)
        else:
            #user token is invalid; fallback to user session authentication
            res = _auth(request)
            if res:
                #already authenticated,but can authorized or not authorized
                logger.debug("Failed to authenticate the user({}) with token, fall back to use session authentication".format(useremail))
                return res
            else:
                #Not authenticated, return basic auth required response
                logger.debug("Failed to authenticate the user({}) with token".format(useremail))
                return basic_auth_required_response_factory(request)

    except Exception as e:
        #return basi auth required response if any exception occured.
        return basic_auth_required_response_factory(request)

email_re = re.compile("^[a-zA-Z0-9\.!#\$\%\&’'\*\+\/\=\?\^_`\{\|\}\~\-]+@[a-zA-Z0-9\-]+(\.[a-zA-Z0-9-]+)*$")
VALID_CODE_CHARS = string.digits if settings.PASSCODE_DIGITAL else (string.ascii_uppercase + string.digits)
VALID_TOKEN_CHARS = string.ascii_uppercase + string.digits

get_verifycode_key = lambda email:"verifycode:{}".format(email)
get_signuptoken_key = lambda email:"signuptoken:{}".format(email)
get_sendcode_number_key = lambda email:"sendcodenumber:{}".format(email)
get_verifycode_number_key = lambda email:"verifycodenumber:{}".format(email)
get_codeid = lambda :"{}.{}".format(timezone.localtime().timestamp(),get_random_string(10,VALID_TOKEN_CHARS))

get_expire_key = lambda key:"{}_expireat".format(key)

def set_expirable_session_data(session,key,value,timeout,now=None):
    now = now or timezone.localtime()
    session[key] = value
    session[get_expire_key(key)] = now + timedelta(seconds=timeout)

def get_expirable_session_data(session,key,default=None,now=None):
    now = now or timezone.localtime()
    expireat = session.get(get_expire_key(key))
    if expireat and now <= expireat:
        return session.get(key) or default
    else:
        return default

def del_expirable_session_data(session,key):
    try:
        del session[get_expire_key(key)]
    except KeyError:
        pass
    try:
        del session[key]
    except KeyError:
        pass

def auth_local(request):
    """
    auth_local feature can be triggered from any domain, but if the request's domain is not the subdomain of the session cookie domain, auth2 will redirect the request to auth2 domain
    and sigin in to auth2 domain first and then signin to other domain via login_domain.
    """
    if request.method == "GET":
        next_url = _get_next_url(request)
    else:
        next_url = request.POST.get("next","")
        if not next_url:
            domain = request.get_host()
            if domain == settings.AUTH2_DOMAIN:
                next_url = "https://{}/sso/setting".format(domain)
            else:
                next_url = "https://{}".format(domain)

    next_url_domain = utils.get_domain(next_url)

    if request.user.is_authenticated:
        #already authenticated
        if next_url_domain.endswith(settings.SESSION_COOKIE_DOMAIN):
            #The domain of next url is the same as session cookie domain, redirect to next url directly
            return HttpResponseRedirect(next_url)
        else:
            #The domain of next url is not the session cookie domain, login to domain first
            return TemplateResponse(request,"authome/login_domain.html",context={"session_key":request.session.cookie_value,"next_url":next_url,"domain":next_url_domain})

    page_layout,extracss = _get_userflow_pagelayout(request,next_url_domain)

    context = {"body":page_layout,"extracss":extracss,"domain":next_url_domain,"next":next_url,"expiretime":utils.format_timedelta(settings.PASSCODE_AGE,unit='s')}

    now = timezone.localtime()
    if request.method == "GET":
        if request.get_host().endswith(settings.SESSION_COOKIE_DOMAIN):
            #request is sent from session cookie domain, show the page to input email
            return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
        else:
            #request is sent from other domain, redirect to auth2 to let user login to session cookie domain first.
            return HttpResponseRedirect("https://{}/sso/auth_local?next={}".format(settings.AUTH2_DOMAIN,urllib.parse.quote(next_url)))
    elif request.method == "POST":
        if not request.get_host().endswith(settings.SESSION_COOKIE_DOMAIN):
            #post request is sent from other domain, invalid, redirect to auth2 to let user login to session cookie domain first
            return HttpResponseRedirect("https://{}/sso/auth_local?next={}".format(settings.AUTH2_DOMAIN,urllib.parse.quote(next_url)))

        #all post auth_local request should come from session cookie domain
        action = request.POST.get("action")
        email = request.POST.get("email","").strip().lower()
        context["email"] = email
        if not action:
            context["messages"] = [("error","Action is missing")]
            context["codeid"] = request.POST.get("codeid")
            return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
        elif action == "cancel":
            return HttpResponseRedirect(next_url)
        elif action == "changeemail":
            context["codeid"] = request.POST.get("codeid")
            return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
        elif action in ( "sendcode","resendcode"):
            if not email:
                context["messages"] = [("error","Email is required")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
            if not email_re.search(email):
                context["messages"] = [("error","Email is invalid")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)

            codeid = request.POST.get("codeid") if action == "sendcode" else None
            code = None
            codekey = get_verifycode_key(email)
            verifycode_number_key = get_verifycode_number_key(email)
            if codeid:
                #a verifycode has already been sent before. reuse it if possible.
                verifycode_number = request.session.get(verifycode_number_key) or 0
                if verifycode_number >= settings.PASSCODE_TRY_TIMES:
                    #The limits of verifying the current code was reached, generate a new one.
                    code = None
                    codeid = None
                else:
                    code = get_expirable_session_data(request.session,codekey,None,now)
                    if code and code.startswith(codeid + "="):
                        #codeid is matched, reuse the existing code
                        context["messages"] = [("info","Verification code has already been sent to {}; Please entery the verification code.".format(email))]
                        logger.debug("Verification code has already been sent to {}, no need to send again".format(context["email"]))
                    else:
                        #code is outdated, generate a new one
                        code = None
                        codeid = None
            if not codeid:
                sendcode_number_key = get_sendcode_number_key(email)
                if defaultcache:
                    sendcode_number = int(defaultcache.get(sendcode_number_key,0) or 0)
                else:
                    sendcode_number = get_expirable_session_data(request.session,sendcode_number_key,0,now)

                if sendcode_number >= settings.PASSCODE_DAILY_LIMIT:
                    #The daily limits of sending veriy code was reached.
                    context["messages"] = [("error","You have exceeded the number of code generation attempts allowed.")]
                    return TemplateResponse(request,"authome/signin_inputemail.html",context=context)

                codeid = get_codeid()
                seconds = now.hour * 60 * 60 + now.minute * 60 + now.second
                if defaultcache:
                    defaultcache.set(sendcode_number_key,sendcode_number + 1,timeout=86400 - seconds)
                else:
                    set_expirable_session_data(request.session,sendcode_number_key , sendcode_number + 1 , 86400 - seconds , now)

                code = get_random_string(settings.PASSCODE_LENGTH,VALID_CODE_CHARS)
                set_expirable_session_data(request.session,codekey,"{}={}".format(codeid,code),settings.PASSCODE_AGE,now)
                request.session[verifycode_number_key] = 0
                context["otp"] = code

                #initialized the userflow if required
                userflow = _get_userflow_verifyemail(request,next_url_domain)

                #get the verificatio email body
                verifyemail_body = userflow.verifyemail_body_template.render(
                    context=context,
                    request=request
                )
                #send email
                emails.send_email(userflow.verifyemail_from,context["email"],userflow.verifyemail_subject,verifyemail_body)
                context["messages"] = [("info","Verification code has been sent to {}; Please enter the verification code.".format(email))]
                logger.debug("Verification code has been sent to {}.".format(context["email"]))
            context["codeid"] = codeid
            return TemplateResponse(request,"authome/signin_verifycode.html",context=context)
        elif action == "verifycode":
            codeid = request.POST.get("codeid")
            if not codeid:
                context["messages"] = [("error","Codeid is missing.")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
            context["codeid"] = codeid

            if not email:
                context["messages"] = [("error","Email is missing.")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
            if not email_re.search(email):
                context["messages"] = [("error","Email is invalid")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)

            inputcode = request.POST.get("code","").strip().upper()
            if not inputcode:
                context["messages"] = [("error","Please input the code to verify.")]
                return TemplateResponse(request,"authome/signin_verifycode.html",context=context)

            context["code"] = inputcode

            verifycode_number_key = get_verifycode_number_key(email)

            codekey = get_verifycode_key(email)
            code = get_expirable_session_data(request.session,codekey,None,now)
            if not code:
                context["messages"] = [("error","The verification code has expired. Send a new code")]
                return TemplateResponse(request,"authome/signin_verifycode.html",context=context)
            elif not code.startswith(codeid + "="):
                context["messages"] = [("error","The verfication code was sent by other device,please resend the code again.")]
                return TemplateResponse(request,"authome/signin_verifycode.html",context=context)
            else:
                verifycode_number = request.session.get(verifycode_number_key) or 0
                if verifycode_number >= settings.PASSCODE_TRY_TIMES:
                    #The limits of verifying the current code was reached,.
                    context["messages"] = [("error","You have exceeded the number({}) of retries allowed.".format(settings.PASSCODE_TRY_TIMES))]
                    return TemplateResponse(request,"authome/signin_verifycode.html",context=context)
                elif code[len(codeid) + 1:] != inputcode:
                    #code is invalid.
                    #increase the failed verifing times.
                    request.session[verifycode_number_key] = verifycode_number + 1
                    context["messages"] = [("error","The input code is invalid, please check the email and verify again.")]
                    return TemplateResponse(request,"authome/signin_verifycode.html",context=context)

            #verify successfully
            user = models.User.objects.filter(email=email).first()
            if user:
                idp,created = models.IdentityProvider.objects.get_or_create(idp=models.IdentityProvider.AUTH_EMAIL_VERIFY[0],defaults={"name":models.IdentityProvider.AUTH_EMAIL_VERIFY[1]})
                update_fields = ["last_login"]
                user.last_login = now

                if user.last_idp != idp:
                    user.last_idp = idp
                    update_fields.append("last_idp")

                dbcagroup = models.UserGroup.dbca_group()
                usergroups = models.UserGroup.find_groups(email)[0]
                if any(group.is_group(dbcagroup) for group in usergroups ):
                    is_staff = True
                    is_superuser = models.can_access(email,settings.AUTH2_DOMAIN,"/admin/")
                else:
                    is_staff = False
                    is_superuser = False
                if user.is_staff != is_staff:
                    user.is_staff = is_staff
                    update_fields.append("is_staff")
                if user.is_superuser != is_superuser:
                    user.is_superuser = is_superuser
                    update_fields.append("is_superuser")

                user.save(update_fields=update_fields)
                if user.is_active:
                    del_expirable_session_data(request.session,codekey)
                    del request.session[verifycode_number_key]
                    request.session["idp"] = idp.idp
                    login(request,user,'django.contrib.auth.backends.ModelBackend')

                    request.session["idp"] = idp.idp
                    timeout = models.UserGroup.get_session_timeout(usergroups)
                    if timeout:
                        request.session["session_timeout"] = timeout

                    if next_url_domain.endswith(settings.SESSION_COOKIE_DOMAIN):
                        return HttpResponseRedirect(next_url)
                    else:
                        return TemplateResponse(request,"authome/login_domain.html",context={"session_key":request.session.cookie_value,"next_url":next_url,"domain":next_url_domain})
                else:
                    return signout(request,next_url=next_url,message="Your account is disabled.",localauth=True)
            else:
                #Userr does not exist, signup
                token = get_random_string(settings.SIGNUP_TOKEN_LENGTH,VALID_TOKEN_CHARS)
                set_expirable_session_data(request.session,get_signuptoken_key(email),token,settings.SIGNUP_TOKEN_AGE,now)
                context["token"] = token
                return TemplateResponse(request,"authome/signin_signup.html",context=context)
        elif action == "signup":
            del_expirable_session_data(request.session,get_verifycode_key(email))
            del request.session[get_verifycode_number_key(email)]
            if not email:
                context["codeid"] = get_codeid()
                context["messages"] = [("error","Email is missing.")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
            if not email_re.search(email):
                context["codeid"] = get_codeid()
                context["messages"] = [("error","Email address is invalid")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
            signuptoken = request.POST.get("token","").strip()
            if not signuptoken:
                context["codeid"] = get_codeid()
                context["messages"] = [("error","Signup token is missing")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)

            tokenkey = get_signuptoken_key(email)
            token = get_expirable_session_data(request.session,tokenkey,None,now)
            if not token:
                context["codeid"] = get_codeid()
                context["messages"] = [("error","The signup token is expired, please signin again.")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
            elif token != signuptoken:
                context["codeid"] = get_codeid()
                context["messages"] = [("error","The signup token is invalid, please signin again")]
                return TemplateResponse(request,"authome/signin_inputemail.html",context=context)

            firstname = request.POST.get("firstname","").strip()
            lastname = request.POST.get("lastname","").strip()
            context["firstname"] = firstname
            context["lastname"] = lastname

            if not firstname:
                context["token"] = token
                context["messages"] = [("error","First name is required")]
                return TemplateResponse(request,"authome/signin_signup.html",context=context)

            if not lastname:
                context["token"] = token
                context["messages"] = [("error","Last name is required")]
                return TemplateResponse(request,"authome/signin_signup.html",context=context)

            dbcagroup = models.UserGroup.dbca_group()
            usergroups = models.UserGroup.find_groups(email)[0]
            if any(group.is_group(dbcagroup) for group in usergroups ):
                is_staff = True
                is_superuser = models.can_access(email,settings.AUTH2_DOMAIN,"/admin/")
            else:
                is_staff = False
                is_superuser = False

            idp,created = models.IdentityProvider.objects.get_or_create(idp=models.IdentityProvider.AUTH_EMAIL_VERIFY[0],defaults={"name":models.IdentityProvider.AUTH_EMAIL_VERIFY[1]})
            user,created = models.User.objects.update_or_create(email=email,username=email,defaults={"is_staff":is_staff,"last_idp":idp,"last_login":now,"first_name":firstname,"last_name":lastname,"is_superuser":is_superuser})

            request.session["idp"] = idp.idp
            del_expirable_session_data(request.session,tokenkey)
            login(request,user,'django.contrib.auth.backends.ModelBackend')

            request.session["idp"] = idp.idp
            timeout = models.UserGroup.get_session_timeout(usergroups)
            if timeout:
                request.session["session_timeout"] = timeout

            if next_url_domain.endswith(settings.SESSION_COOKIE_DOMAIN):
                return HttpResponseRedirect(next_url)
            else:
                return TemplateResponse(request,"authome/login_domain.html",context={"session_key":request.session.cookie_value,"next_url":next_url,"domain":next_url_domain})
        else:
            context["messages"] = [("error","Action({}) Not Support".format(action))]
            context["codeid"] = get_codeid()
            return TemplateResponse(request,"authome/signin_inputemail.html",context=context)
    else:
        return  HttpResponseNotAllowed(["GET","POST"])


def logout_view(request):
    """
    View method for path '/sso/auth_logout'
    """
    from ..backends import AzureADB2COAuth2
    host = request.get_host()
    if not host.endswith(settings.SESSION_COOKIE_DOMAIN):
        #request's domain is not a subdomain of session cookie; only need to delete to cookie ; and redirect to auth2.dbca to finish the logout procedure.
        parameters = dict(request.GET.items())
        parameters["domain"] = host
        querystring = encode_url_parameters(parameters)
        url = "https://{}/sso/auth_logout?{}".format(settings.AUTH2_DOMAIN,querystring)
        #delete the session cookie from browser via setting the session_key to None
        request.session._session_key = None
        request.session.clear()
        return HttpResponseRedirect(url)
    #get post logout url
    post_logout_url = get_post_b2c_logout_url(request,encode=False)
    if "localauth" in request.GET:
        logout_url = post_logout_url
    else:
        #get backend logout url
        backend_logout_url = AzureADB2COAuth2.get_logout_url() #request.session.get("backend_logout_url")
        logout_url = backend_logout_url.format(urllib.parse.quote(post_logout_url))

    logout(request)
    return HttpResponseRedirect(logout_url)

SessionEngine = import_module(settings.SESSION_ENGINE)
SessionStore = SessionEngine.SessionStore
def login_domain(request):
    """
    Login to other domain
    """
    session_cookie = request.POST.get("session")
    next_url = request.POST.get("next_url")
    if not next_url:
        next_url = "https://{}".format(request.get_host())

    if not session_cookie:
        #missing session key, login again
        return HttpResponse(content="session is missing",status=400)

    res = HttpResponseRedirect(next_url)
    max_age = request.session.get_session_cookie_age(session_cookie)
    expires_time = time.time() + max_age
    expires = http_date(expires_time)
    host = request.get_host()
    domain = settings.GET_SESSION_COOKIE_DOMAIN(request.get_host())
    res.set_cookie(
        settings.SESSION_COOKIE_NAME,
        "{}{}{}".format(session_cookie,settings.SESSION_COOKIE_DOMAIN_SEPARATOR,domain or host),
        max_age=max_age,
        expires=expires,
        path=settings.SESSION_COOKIE_PATH,
        domain=domain,
        secure=settings.SESSION_COOKIE_SECURE or None,
        httponly=settings.SESSION_COOKIE_HTTPONLY or None,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    DebugLog.log(DebugLog.CREATE_COOKIE,utils.get_lb_hash_key(session_cookie),utils.get_clusterid(session_cookie),utils.get_session_key(session_cookie),session_cookie,message="Return a new session cookie({}) for domain({})".format("{}{}{}".format(session_cookie,settings.SESSION_COOKIE_DOMAIN_SEPARATOR,domain or host),domain or host),userid=None,target_session_cookie="{}{}{}".format(session_cookie,settings.SESSION_COOKIE_DOMAIN_SEPARATOR,domain or host),request=request)
    return res


def home(request):
    """
    View method for path '/'
    redirect to next url if authenticated and authorized;
    redirect to '/sso/forbidden' if authenticated but not authorized
    Trigger authentication user flow if not authenticated
    """
    next_url = request.GET.get('next', None)
    if next_url:
        #build an absolute url
        if not next_url.startswith("http"):
            if next_url[0] == "/":
                host = request.get_host()
                next_url = "https://{}{}".format(host,next_url)
            else:
                next_url = "https://{}".format(next_url)

    if next_url and "?" in next_url:
        next_path = next_url[0:next_url.index('?')]
    else:
        next_path = next_url
    #check whether rquest is authenticated and authorized
    if not request.user.is_authenticated or not request.user.is_active:
        if next_path and any(next_path.endswith(p) for p in ["/sso/auth_logout","/sso/signedout","/sso/signout_socialmedia"]):
            #next path is signout url
            #if have relogin parameter, try to use relogin url as next_url
            relogin_url = None
            if "?" in next_url:
                parameters = dict([ (p.split("=",1) if "=" in p else (p,"")) for p in next_url[next_url.index("?") + 1:].split("&") if p.strip()])
                if parameters.get("relogin"):
                    relogin_url = urllib.parse.unquote(parameters.get("relogin"))
                    if not relogin_url.startswith("http"):
                        relogin_url = "https://{}{}".format(utils.get_domain(next_url) or request.get_host(),relogin_url)

            if relogin_url:
                next_url = relogin_url
                if not next_url.startswith("http"):
                    if next_url[0] == "/":
                        host = utils.get_domain(next_path)
                        next_url = "https://{}{}".format(host,next_url)
                    else:
                        next_url = "https://{}".format(next_url)
            else:
                #can't find next_url, use default next_url
                host = utils.get_domain(next_path)
                if host == settings.AUTH2_DOMAIN:
                    next_url = "https://{}/sso/setting".format(host)
                else:
                    next_url = "https://{}".format(host)

            request.session["next"]=next_url
            return logout_view(request)

        if (not request.user.is_authenticated and request.session.expired_session_key) or (request.user.is_authenticated and not request.user.is_active):
            #session expired or user is inactive, logout from backend
            request.session["next"]=next_url
            return logout_view(request)
        else:
            #not authenticated, authenticate user via azure b2c
            url = reverse('social:begin', args=['azuread-b2c-oauth2'])
            if next_url:
                #has next_url, add next url to authentication url as url parameter
                next_url_domain = utils.get_domain(next_url)
                if next_url_domain and not next_url_domain.endswith(settings.SESSION_COOKIE_DOMAIN):
                    #crosss domain authentication
                    next_url = "https://{}?{}".format(settings.AUTH2_DOMAIN,urlencode({'next': next_url}))
                url = '{}?{}'.format(url,urlencode({'next': next_url}))
            else:
                #no next_url, clean the next url  from session
                try:
                    del request.session[REDIRECT_FIELD_NAME]
                except:
                    pass
            logger.debug("sso auth url = {}".format(url))
            #redirect to authentiocaion url to start authentication user flow
            return HttpResponseRedirect(url)
    else:
        #authenticated , redirect to the original request
        if not next_url:
            host = request.get_host()
            if host == settings.AUTH2_DOMAIN:
                next_url = "https://{}/sso/setting".format(host)
                logger.debug("Use the default auth2 next url '{}'".format(next_url))
            else:
                next_url = "https://{}".format(host)
                logger.debug("Use the default client app next url '{}'".format(next_url))
        elif any(next_path.endswith(p) for p in ["/sso/auth_logout","/sso/signedout"]):
            #next url is a signout url, try to get the next url from signout url
            relogin_url = None
            if "?" in next_url:
                parameters = dict([ (p.split("=",1) if "=" in p else (p,"")) for p in next_url[next_url.index("?") + 1:].split("&") if p.strip()])
                if parameters.get("relogin"):
                    relogin_url = urllib.parse.unquote(parameters.get("relogin"))
                    if not relogin_url.startswith("http"):
                        relogin_url = "https://{}{}".format(utils.get_domain(next_url) or request.get_host(),relogin_url)

            if relogin_url:
                next_url = relogin_url
                if not next_url.startswith("http"):
                    if next_url[0] == "/":
                        host = utils.get_domain(next_path)
                        next_url = "https://{}{}".format(host,next_url)
                    else:
                        next_url = "https://{}".format(next_url)
                logger.debug("Use the relogin url({}) as  next url ".format(next_url))
            else:
                host = utils.get_domain(next_path)
                if host == settings.AUTH2_DOMAIN:
                    next_url = "https://{}/sso/setting".format(host)
                    logger.debug("Can't find the relogin url, use the default auth2 next url '{}'".format(next_url))
                else:
                    next_url = "https://{}".format(host)
                    logger.debug("Can't find the relogin url, use the default client app next url '{}'".format(next_url))
        else:
            logger.debug("Get the next url '{}'".format(next_url))
            pass

        #has next_url, redirect to that url
        next_url_domain = utils.get_domain(next_url)
        if next_url_domain.endswith(settings.SESSION_COOKIE_DOMAIN):
            #in the same session domain, redirect to the orignal url directly
            return HttpResponseRedirect(next_url)
        else:
            #other domain, login to that before redirecting to the original url
            return TemplateResponse(request,"authome/login_domain.html",context={"session_key":request.session.cookie_value,"next_url":next_url,"domain":next_url_domain})

def loginstatus(request):
    """
    View method for path '/sso/loginstatus'
    Return a page to indicate the login status
    """
    res = _auth(request)

    domain = request.get_host()
    page_layout,extracss = _get_userflow_pagelayout(request,domain)

    context = {"body":page_layout,"extracss":extracss,"message":"You {} signed in".format("have already" if res else "haven't"),"title":"Login Status","domain":domain}

    return TemplateResponse(request,"authome/message.html",context=context)



def profile(request):
    """
    View method for path '/sso/profile'
    Must called after authentication
    Return the authenticated user profile as json
    """
    #get the auth response
    user = request.user
    if not user.is_authenticated:
        #not authenticated
        return HttpResponse(content=json.dumps({"authenticated":False}),content_type="application/json")
    auth_key = request.session.session_key
    response = None if (request.session.cookie_changed or request.session.is_empty()) else cache.get_auth(user,auth_key,user.modified)

    if not response:
        response = _populate_response(request,cache.set_auth,auth_key,user,request.session.cookie_value)

    #populte the profile from response headers
    content = {"authenticated":True}
    for key,value in response.items():
        if key.startswith("X-"):
            key = key[2:].replace("-","_")
            content[key] = value

    current_ip,routable = get_client_ip(request)
    content['client_logon_ip'] = current_ip
    #populate the user token property
    try:
        token = models.UserToken.objects.filter(user = user).first()
        if not token or not token.enabled:
            content["access_token_error"] = "Access token is not enabled, please ask administrator to enable."
        elif not token.token:
            content["access_token_error"] = "Access token is not created, please ask administrator to create"
        elif token.is_expired:
            content["access_token"] = token.token
            content["access_token_created"] = timezone.localtime(token.created).strftime("%Y-%m-%d %H:%M:%S")
            content["access_token_expireat"] = token.expired.strftime("%Y-%m-%d")
            content["access_token_error"] = "Access token is expired, please ask administrator to recreate"
        else:
            content["access_token"] = token.token
            content["access_token_created"] = timezone.localtime(token.created).strftime("%Y-%m-%d %H:%M:%S")
            if token.expired:
                content["access_token_expireat"] = token.expired.strftime("%Y-%m-%d 23:59:59")
    except Exception as ex:
        logger.error("Failed to get access token for the user({}).{}".format(user.email,traceback.format_exc()))
        content["access_token_error"] = str(ex)
    if request.session.get("mfa_method"):
        content["mfa_method"] = MFA_METHOD_MAPPING.get(request.session["mfa_method"],request.session["mfa_method"])
    if request.session.get("idp"):
        content["idp"] = models.IdentityProvider.objects.get(idp=request.session["idp"]).name


    content = json.dumps(content)
    return HttpResponse(content=content,content_type="application/json")

def signout_socialmedia(request):
    """
    View method for path '/sso/signout_socialmedia'
    Return a consistent signedout page
    """
    if request.user.is_authenticated:
        #this is not a normal request, must send by user manually.
        #still authenticated, sigout first
        return logout_view(request)

    domain = request.get_host()
    page_layout,extracss = _get_userflow_pagelayout(request,domain)

    context = {
        "body":page_layout,
        "extracss":extracss,
        "domain":domain,
        "signedout":  request.GET.get("signedout") or "/sso/signedout",
        "message":request.GET.get("message") or ""
    }
    context["idp"] = request.GET.get("idp")
    context["idplogout"] = request.GET.get("idplogout")

    if context["message"]:
        context["failed_message"] = "{}\r\nFailed to logout from the social media '{}' because popup window was blocked".format(context["message"],context["idp"])
    else:
        context["failed_message"] = "Failed to logout from the social media '{}' because popup window was blocked".format(context["idp"])

    if request.GET.get("relogin"):
        context["relogin"] = request.GET.get("relogin")
    else:
        userflow_signout =  _get_userflow_signout(request,domain)
        if userflow_signout.relogin_url:
            context["relogin"] = userflow_signout.relogin_url
        elif domain == settings.AUTH2_DOMAIN:
            context["relogin"] = "/sso/setting"
        else:
            context["relogin"] = "/"

    return TemplateResponse(request,"authome/signout_socialmedia.html",context=context)

def signedout(request):
    """
    View method for path '/sso/signedout'
    Return a consistent signedout page
    """
    if request.user.is_authenticated:
        #this is not a normal request, must send by user manually.
        #still authenticated, sigout first
        return logout_view(request)

    domain = request.get_host()
    page_layout,extracss = _get_userflow_pagelayout(request,domain)
    userflow_signout =  _get_userflow_signout(request,domain)

    context = {
        "body":page_layout,
        "extracss":extracss,
        "domain":domain,
        "message":request.GET.get("message")
    }
    if request.GET.get("idp"):
        context["idp"] = request.GET.get("idp")
        context["idplogout"] = request.GET.get("idplogout")

    if request.GET.get("relogin"):
        context["relogin"] = request.GET.get("relogin")
    else:
        if userflow_signout.relogin_url:
            context["relogin"] = userflow_signout.relogin_url
        elif domain == settings.AUTH2_DOMAIN:
            context["relogin"] = "/sso/setting"
        else:
            context["relogin"] = "/"

    signout_body = userflow_signout.signout_body_template.render(
        context=context,
        request=request
    )
    context["signout_content"] = signout_body

    return TemplateResponse(request,"authome/signedout.html",context=context)

def signout(request,next_url=None,message=None,idp=None,localauth=False):
    """
    Called by pipeline to automatically logout the user beceause some errors occured druing authentication.
    """
    parameters = {}
    domain = request.get_host()

    if not next_url:
        #next url is empty,try to find the next url from session
        next_url = request.session.get("next")

    if next_url:
        url_map = utils.parse_url(next_url)
        if url_map["domain"] == settings.AUTH2_DOMAIN and (url_map["path"] == "" or url_map["path"] == "/"):
            #is auth2 home path, try to find the real next url
            if url_map["parameters"]:
                parameters = dict([ (p.split("=",1) if "=" in p else (p,"")) for p in url_map["parameters"].split("&") if p.strip()])
                if parameters.get("next"):
                    next_url = urllib.parse.unquote(parameters.get("next"))

    if next_url:
        url_domain,next_url = utils.get_domain_path(next_url)
        if url_domain:
            domain = url_domain
    else:
        #still can't get the relogin url, use the home page of the domain as relogin url
        if domain == settings.AUTH2_DOMAIN:
            next_url = "/sso/setting"
        else:
            next_url = "/"

    parameters["next"] = next_url

    if idp:
        parameters["idp"] = idp.id
    else:
        idpid = request.session.get("idp")
        if idpid:
            idp = models.IdentityProvider.get_idp(idp)
            if idp:
                parameters["idp"] = idp.id

    if message:
        parameters["message"] = message

    if localauth:
        parameters["localauth"] = ""

    logout(request)

    querystring = encode_url_parameters(parameters)
    if querystring:
        return HttpResponseRedirect("https://{}/sso/auth_logout?{}".format(domain,querystring))
    else:
        return HttpResponseRedirect("https://{}/sso/auth_logout".format(domain))


def _init_userflow_pagelayout(request,userflow,container_class):
    """
    Initialize the pagelayout for the custmizable userflow and container_class
    """
    logger.debug("Initialize user flow page layout; userflow={}, container_class={}".format(userflow,container_class))
    #initialize the page layout for the user userflow and container class

    if userflow.pagelayout_customized == False:
        #no customization
        return
    elif userflow.pagelayout_customized and hasattr(userflow,container_class):
        #initied for the container class
        return

    if userflow.pagelayout_customized is None and userflow.defaultuserflow and not userflow.page_layout and not userflow.extracss:
        #no customization
        userflow.pagelayout_customized = False
        return

    if userflow.page_layout:
        #page_layout is configured, init page_layout using template engine
        context={"container_class":container_class}
        page_layout = userflow.page_layout

        page_layout = django_engine.from_string(page_layout).render(
            context=context,
            request=request
        )
        setattr(userflow,container_class,page_layout)
    else:
         #page_layout is not configured, use default userflow's page_layout
         #initialize default userflow
        _init_userflow_pagelayout(request,userflow.defaultuserflow,container_class)
        #set userflow's page layout to default userflow's page layout
        setattr(userflow,container_class,getattr(userflow.defaultuserflow,container_class))

    if not userflow.pagelayout_customized:
        #only need to init once
        if userflow.extracss or not userflow.defaultuserflow:
            #init extracss using template engine
            extracss = userflow.extracss or ""
            userflow.inited_extracss = django_engine.from_string(extracss).render(
                context=context,
                request=request
            )

        else:
            _init_userflow_pagelayout(request,userflow.defaultuserflow,container_class)
            userflow.inited_extracss = userflow.defaultuserflow.inited_extracss

        userflow.pagelayout_customized = True

def _get_userflow_pagelayout(request,domain,container_class="self_asserted_container"):
    userflows = models.CustomizableUserflow.find_userflows(domain)
    for userflow in userflows:
        _init_userflow_pagelayout(request,userflow,container_class)

        if userflow.pagelayout_customized:
            return (getattr(userflow,container_class),userflow.inited_extracss)

def _init_userflow_verifyemail(request,userflow):
    """
    Initialize the verifyemail for customizable userflow object
    """
    if userflow.verifyemail_customized == False:
        #no customization
        return
    elif userflow.verifyemail_customized:
        #initied
        return

    if userflow.verifyemail_customized is None and userflow.defaultuserflow and not userflow.verifyemail_from and not userflow.verifyemail_subject and not userflow.verifyemail_body:
        #no customization
        userflow.verifyemail_customized = False
        return

    #initialize verifyemail related properties
    if not userflow.verifyemail_from:
        #verifyemail_from is not configured, get it from default userflow
        _init_userflow_verifyemail(request,userflow.defaultuserflow)
        userflow.verifyemail_from = userflow.defaultuserflow.verifyemail_from

    if not userflow.verifyemail_subject:
        #verifyemail_subject is not configured, get it from default userflow
        _init_userflow_verifyemail(request,userflow.defaultuserflow)
        userflow.verifyemail_subject = userflow.defaultuserflow.verifyemail_subject

    if userflow.verifyemail_body:
        #verifyemail_body is configured, get it from template
        userflow.verifyemail_body_template = django_engine.from_string(userflow.verifyemail_body)
    else:
        #verifyemail_body is not configured, get it from default userflow
        _init_userflow_verifyemail(request,userflow.defaultuserflow)
        userflow.verifyemail_body_template = userflow.defaultuserflow.verifyemail_body_template

    userflow.verifyemail_customized = True

def _get_userflow_verifyemail(request,domain):
    userflows = models.CustomizableUserflow.find_userflows(domain)
    for userflow in userflows:
        _init_userflow_verifyemail(request,userflow)
        if userflow.verifyemail_customized:
            return userflow

def _init_userflow_signout(request,userflow):
    """
    Initialize the verifyemail for customizable userflow object
    """
    if userflow.signout_customized == False:
        #no customization
        return
    elif userflow.signout_customized:
        #initied
        return

    if userflow.signout_customized is None and userflow.defaultuserflow and not userflow.signedout_url and not userflow.relogin_url and not userflow.signout_body:
        #no customization
        userflow.signout_customized = False
        return

    #initialize verifyemail related properties
    if not userflow.signedout_url and userflow.defaultuserflow:
        #verifyemail_from is not configured, get it from default userflow
        _init_userflow_signout(request,userflow.defaultuserflow)
        userflow.signedout_url = userflow.defaultuserflow.signedout_url

    if not userflow.relogin_url and userflow.defaultuserflow:
        #verifyemail_subject is not configured, get it from default userflow
        _init_userflow_signout(request,userflow.defaultuserflow)
        userflow.relogin_url = userflow.defaultuserflow.relogin_url

    if userflow.signout_body:
        #verifyemail_body is configured, get it from template
        userflow.signout_body_template = django_engine.from_string(userflow.signout_body)
    else:
        #verifyemail_body is not configured, get it from default userflow
        _init_userflow_signout(request,userflow.defaultuserflow)
        userflow.signout_body_template = userflow.defaultuserflow.signout_body_template

    userflow.signout_customized = True


def _get_userflow_signout(request,domain):
    userflows = models.CustomizableUserflow.find_userflows(domain)
    for userflow  in userflows:
        _init_userflow_signout(request,userflow)
        if userflow.signout_customized:
            return userflow

def adb2c_view(request,template,**kwargs):
    """
    View method for path '/sso/xxx.html'
    Used by b2c to provide the customized page layout
    three optional url parameters
      domain: the app domain used to provide customization per app
      container_class: the css class used in page layout, it should be the same css class as the css class used in builtin css copied from b2c default template.
      title: page title, defaule is "Signup or Singin"
    """
    domain = request.GET.get('domain', None)
    container_class = request.GET.get('class')
    header = request.GET.get('header')
    footer = request.GET.get('footer')
    title = request.GET.get('title', "Signup or Signin")
    return domain_related_page(request,template,domain,title,container_class=container_class,header=header,footer=footer)

def domain_related_page(request,template,domain,title,container_class=None,header=None,footer=None):
    """
    View method for path '/sso/xxx.html'
    Used by b2c to provide the customized page layout
    three optional url parameters
      domain: the app domain used to provide customization per app
      container_class: the css class used in page layout, it should be the same css class as the css class used in builtin css copied from b2c default template.
      title: page title, defaule is "Signup or Singin"
    """
    if not container_class:
        container_class = "{}_container".format(template)
    logger.debug("Request the customized authentication interface for domain({}) and container_class({})".format(domain,container_class))

    page_layout,extracss = _get_userflow_pagelayout(request,domain,container_class=container_class)

    context = {
        "body":page_layout,
        "extracss":extracss,
        "title":title,
        "enable_b2c_js_extension":settings.ENABLE_B2C_JS_EXTENSION,
        "header":header or "",
        "footer":footer or "",
        "add_auth2_local_option":settings.ADD_AUTH2_LOCAL_OPTION,
        "domain" : settings.AUTH2_DOMAIN
    }

    return TemplateResponse(request,"authome/{}.html".format(template),context=context)

def forbidden(request):
    """
    View method for path '/sso/forbidden'
    can also be called from other view method
    Provide a consistent,customized forbidden page.
    """
    url = get_absolute_url(request.GET.get("path") or request.get_full_path(),request.get_host())
    parsed_url = utils.parse_url(url)
    domain = parsed_url["domain"]
    path = parsed_url["path"]

    page_layout,extracss = _get_userflow_pagelayout(request,domain)

    context = {"body":page_layout,"extracss":extracss,"path":path,"url":url.format(domain,path),"domain":domain}

    return TemplateResponse(request,"authome/forbidden.html",context=context)

def profile_edit(request):
    """
    View method for path '/sso/profile/edit'
    """
    def _get_context(next_url):
        domain = utils.get_domain(next_url)
        page_layout,extracss = _get_userflow_pagelayout(request,domain)

        return {"body":page_layout,"extracss":extracss,"domain":domain,"next":next_url,"user":request.user}


    if request.method == "GET":
        next_url = _get_next_url(request)
        context = _get_context(next_url)
        return TemplateResponse(request,"authome/profile_edit.html",context=context)
    else:
        next_url = request.POST.get("next")

        action = request.POST.get("action")
        if action == "change":
            first_name = (request.POST.get("first_name") or "").strip()
            last_name = (request.POST.get("last_name") or "").strip()
            if not first_name:
                context = _get_context(next_url)
                context["messages"] = [("error","Fist name is empty")]
                return TemplateResponse(request,"authome/profile_edit.html",context=context)
            if not last_name:
                context = _get_context(next_url)
                context["messages"] = [("error","Last name is empty")]
                return TemplateResponse(request,"authome/profile_edit.html",context=context)

            if request.user.first_name != first_name or request.user.last_name != last_name:
                request.user.first_name = first_name
                request.user.last_name = last_name
                request.user.save(update_fields=["first_name","last_name","modified"])

        next_url_parsed = utils.parse_url(next_url)
        if next_url_parsed["path"].startswith("/sso/profile"):
            if next_url_parsed["domain"]:
                if next_url_parsed["parameters"]:
                    next_url = "https://{}/sso/setting?{}".format(next_url_parsed["domain"],next_url_parsed["parameters"])
                else:
                    next_url = "https://{}/sso/setting".format(next_url_parsed["domain"])
            else:
                if next_url_parsed["parameters"]:
                    next_url = "/sso/setting?{}".format(next_url_parsed["parameters"])
                else:
                    next_url = "/sso/setting"

        return HttpResponseRedirect(next_url)


@never_cache
@psa("/sso/profile/edit/complete")
def profile_edit_b2c(request,backend):
    """
    View method for path '/sso/profile/edit'
    Start a profile edit user flow
    called after user authentication
    """
    next_url = _get_next_url(request)
    domain = utils.get_domain(next_url)

    request.session[REDIRECT_FIELD_NAME] = next_url
    request.policy = models.CustomizableUserflow.get_userflow(domain).profile_edit
    return do_auth(request.backend, redirect_name="__already_set")

def _do_login(*args,**kwargs):
    """
    Dummy login method
    """
    pass

@never_cache
@csrf_exempt
@psa("/sso/profile/edit/complete")
def profile_edit_complete(request,backend,*args,**kwargs):
    """
    View method for path '/sso/profile/edit/complete'
    Callback url from b2c to complete a user profile editing request
    """
    domain = utils.get_domain(request.session.get(utils.REDIRECT_FIELD_NAME))
    request.policy = models.CustomizableUserflow.get_userflow(domain).profile_edit
    request.http_error_code = 417
    request.http_error_message = "Failed to edit user profile.{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)

@never_cache
@psa("/sso/password/reset/complete")
def password_reset(request,backend):
    """
    View method for path '/sso/password/reset'
    Start a password reset user flow
    Triggered by hyperlink 'Forgot your password' in idp selection page
    """
    next_url = _get_next_url(request)
    domain = utils.get_domain(next_url)

    request.session[REDIRECT_FIELD_NAME] = next_url
    request.policy = models.CustomizableUserflow.get_userflow(domain).password_reset
    return do_auth(request.backend, redirect_name="__already_set")

@never_cache
@csrf_exempt
@psa("/sso/password/reset/complete")
def password_reset_complete(request,backend,*args,**kwargs):
    """
    View method for path '/sso/password/reset/complete'
    Callback url from b2c to complete a user password reset request
    """
    domain = utils.get_domain(request.session.get(utils.REDIRECT_FIELD_NAME))
    request.policy = models.CustomizableUserflow.get_userflow(domain).password_reset
    request.http_error_code = 417
    request.http_error_message = "Failed to reset password.{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)

@never_cache
@psa("/sso/mfa/set/complete")
def mfa_set(request,backend):
    """
    View method for path '/sso/mfa/set'
    Start a user mfa set user flow
    called after user authentication
    """
    next_url = _get_next_url(request)
    domain = utils.get_domain(next_url)

    request.session[REDIRECT_FIELD_NAME] = next_url
    request.policy = models.CustomizableUserflow.get_userflow(domain).mfa_set
    return do_auth(request.backend, redirect_name="already_set")

@never_cache
@csrf_exempt
@psa("/sso/mfa/set/complete")
def mfa_set_complete(request,backend,*args,**kwargs):
    """
    View method for path '/sso/mfa/set/complete'
    Callback url from b2c to complete a user mfa set request
    """
    domain = utils.get_domain(request.session.get(utils.REDIRECT_FIELD_NAME))
    request.policy = models.CustomizableUserflow.get_userflow(domain).mfa_set
    request.http_error_code = 417
    request.http_error_message = "Failed to set mfa method.{}"
    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)


@never_cache
@psa("/sso/mfa/reset/complete")
def mfa_reset(request,backend):
    """
    View method for path '/sso/mfa/set'
    Start a user mfa set user flow
    called after user authentication
    """
    next_url = _get_next_url(request)
    domain = utils.get_domain(next_url)

    request.session[REDIRECT_FIELD_NAME] = next_url
    request.policy = models.CustomizableUserflow.get_userflow(domain).mfa_reset
    return do_auth(request.backend, redirect_name="already_set")

@never_cache
@csrf_exempt
@psa("/sso/mfa/reset/complete")
def mfa_reset_complete(request,backend,*args,**kwargs):
    """
    View method for path '/sso/mfa/set/complete'
    Callback url from b2c to complete a user mfa set request
    """
    domain = utils.get_domain(request.session.get(utils.REDIRECT_FIELD_NAME))
    request.policy = models.CustomizableUserflow.get_userflow(domain).mfa_reset
    request.http_error_code = 417
    request.http_error_message = "Failed to set mfa method.{}"
    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)


bearer_token_re = re.compile("^Bearer\s+(?P<token>\S+)\s*$")
def _auth_bearer(request):
    """
    Check the bearer authentication
    Return True if authenticated; otherwiser return False
    """
    bearer_auth = request.META.get('HTTP_AUTHORIZATION').strip() if 'HTTP_AUTHORIZATION' in request.META else ''
    m = bearer_token_re.search(bearer_auth)
    token = None
    if m:
        token = m.group('token')
    if token != settings.SECRET_KEY:
        logger.debug("Access token is outdated.")
        return False
    return True


@never_cache
@csrf_exempt
def verify_code_via_email(request):
    """
    View method for path '/sso/verifycode'
    Send verification code via email.
    Provide verification email customization
    """
    #authenticate the request
    if not _auth_bearer(request):
        #not authenticated
        return forbidden_response_factory(request)

    #get the domain from request url parameters
    domain = request.GET.get('domain', None)
    userflow = _get_userflow_verifyemail(request,domain)

    data = json.loads(request.body.decode())
    data["email"] = data.get("email","userEmail")

    #get the verificatio email body
    verifyemail_body = userflow.verifyemail_body_template.render(
        context=data,
        request=request
    )
    #send email
    emails.send_email(userflow.verifyemail_from,data["email"],userflow.verifyemail_subject,verifyemail_body)
    logger.debug("Successfully send verification email to '{}',domain is '{}'".format(data["email"],domain))
    return succeed_response_factory(request)

user_totp_key_chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
@never_cache
@csrf_exempt
def totp_generate(request):
    """
    View method for path '/sso/totp/generate'
    """
    result = {
      "version": "1.0.0",
      "status": 409,
    }
    #authenticate the request
    if not _auth_bearer(request):
        #not authenticated
        result["status"] = 400
        result["userMessage"] = "Authorization failed."
        return JsonResponse(result,status=400)

    #get the user email
    data = json.loads(request.body.decode())
    user_email = data.get("email")
    if not user_email:
        logger.debug("Email is missing")
        result["status"] = 400
        result["userMessage"] = "Email is missing"
        return JsonResponse(result,status=400)

    #regenerate flag, currently it is not used in custom policy
    regenerate = data.get("regenerate",False)

    #get the user totp object
    user_totp = models.UserTOTP.objects.filter(email=user_email).first()
    if not user_totp or regenerate:
        #not exist or require regenerating again
        #generate a new code
        if not user_totp:
            user_totp = models.UserTOTP(email=user_email)
        user_totp.secret_key = base64.b32encode(bytearray(get_random_string(settings.TOTP_SECRET_KEY_LENGTH,user_totp_key_chars),'ascii')).decode().rstrip("=")
        user_totp.timestep = settings.TOTP_TIMESTEP
        user_totp.issuer = settings.TOTP_ISSUER.replace(" ","-")
        user_totp.name = user_email
        user_totp.prefix = (settings.TOTP_PREFIX or settings.TOTP_ISSUER).replace(" ","-")
        user_totp.digits = settings.TOTP_DIGITS
        user_totp.algorithm = settings.TOTP_ALGORITHM
        user_totp.created = timezone.localtime()
        user_totp.verified = None
        user_totp.last_verified_code = None

        user_totp.save()
        logger.debug("Generate secret key for user({})".format(user_email))

    #get the totp url
    totpurl = utils.get_totpurl(user_totp.secret_key,user_totp.name,user_totp.issuer,user_totp.timestep,user_totp.prefix,algorithm=user_totp.algorithm,digits=user_totp.digits)
    #generate the qrcode and encode it as base64 string
    qrcode = utils.encode_qrcode(totpurl)

    data = {
        "qrCode" : "{} {}".format(totpurl,qrcode)
    }

    return JsonResponse(data,status=200)


@never_cache
@csrf_exempt
def totp_verify(request):
    """
    View method for path '/sso/totp/verify'
    """
    result = {
      "version": "1.0.0",
      "status": 409,
    }
    #authenticate the request
    if not _auth_bearer(request):
        #not authenticated
        result["status"] = 401
        result["userMessage"] = "Authorization failed."
        return JsonResponse(result,status=400)

    #get the useremail and totpcode
    data = json.loads(request.body.decode())
    logger.debug("verify totp code.{}".format(data))
    user_email = data.get("email")
    if not user_email:
        result["status"] = 400
        result["userMessage"] = "Email is missing"
        return JsonResponse(result,status=400)

    totpcode = data.get("totpCode")
    if not totpcode:
        result["status"] = 400
        result["userMessage"] = "Verification code is missing"
        return JsonResponse(result,status=400)

    user_totp = models.UserTOTP.objects.filter(email=user_email).first()
    if not user_totp :
        #can't find user totp object
        result["status"] = 400
        result["userMessage"] = "Can't find auth app data, please reregister auth app again"
        return JsonResponse(result,status=400)

    if settings.TOTP_CHECK_LAST_CODE and totpcode == user_totp.last_verified_code:
        #totpcode is the last checked totp code,
        result["status"] = 409
        result["userMessage"] = "Verification code was already used."
        return JsonResponse(result,status=409)

    totp = TOTP(user_totp.secret_key,digits=user_totp.digits,digest=utils.get_digest_function(user_totp.algorithm)[1],name=user_totp.name,issuer=user_totp.issuer,interval=user_totp.timestep)
    if totp.verify(totpcode,valid_window=settings.TOTP_VALIDWINDOW):
        #verified
        user_totp.last_verified_code = totpcode
        user_totp.last_verified = timezone.localtime()
        user_totp.save(update_fields=["last_verified","last_verified_code"])
        logger.debug("Succeed to verify totp code.{}".format(data))
        return succeed_response_factory(request)
    else:
        #verify failed.
        logger.debug("Failed to verify totp code.{}".format(data))

        result["status"] = 409
        result["userMessage"] = "Verification code is incorrect."
        return JsonResponse(result,status=409)

def handler400(request,exception,**kwargs):
    """
    Customizable handler to process 400 response.
    This method provide a hook to let exception return its own response
    """
    if isinstance(exception,UserDoesNotExistException):
        if request.path == "/sso/auth":
            return auth_required_response_factory(request)
        elif request.path == "/sso/auth_optional":
            return auth_not_required_response_factory(request)
        else:
            request.user = anonymoususer
            return logout_view(request)
    elif isinstance(exception,HttpResponseException):
        res = exception.get_response(request)
        if res:
            return res
        elif settings.DEBUG:
            message = str(exception)
        else:
            if request.session.get(REDIRECT_FIELD_NAME):
                message = mark_safe("Sign in session is expired, please click <a = href='{}'>here</a> to sign in again.".format(request.session.get(REDIRECT_FIELD_NAME)))
            else:
                message = mark_safe("Sign in session is expired, please signin again.")
    elif isinstance(exception,AuthException):
        if request.session.get(REDIRECT_FIELD_NAME):
            message = mark_safe("Sign in session is expired, please click <a = href='{}'>here</a> to sign in again.".format(request.session.get(REDIRECT_FIELD_NAME)))
        else:
            message = mark_safe("Sign in session is expired, please signin again.")
    elif isinstance(exception,PolicyNotConfiguredException):
        message = str(exception)
    else:
        message = str(exception)

    domain = request.get_host()
    if domain == settings.AUTH2_DOMAIN:
        domain = utils.get_domain(request.session.get(utils.REDIRECT_FIELD_NAME)) or domain
    elif not domain:
        domain = settings.AUTH2_DOMAIN
        
        
    page_layout,extracss = _get_userflow_pagelayout(request,domain)

    context = {"body":page_layout,"extracss":extracss,"message":message,"title":"Authentication failed." if request.path.startswith("/sso/") else "Error","domain":domain}

    code = exception.http_code if (hasattr(exception,"http_code") and exception.http_code) else 400
    resp = TemplateResponse(request,"authome/message.html",context=context,status=code)
    resp.render()
    return resp

def checkauthorization(request):
    if request.method == "GET":
        return TemplateResponse(request, "authome/check_authorization.html", {"users":"","opts":None})

    try:
        default_domain = request.get_host()
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


