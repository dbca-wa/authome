from django.http import HttpResponseRedirect, HttpResponse, HttpResponseForbidden,JsonResponse
from django.template.response import TemplateResponse
from django.contrib.auth import login, logout
from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.http import urlencode
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from django.views.decorators.cache import never_cache
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.template import engines
from django.utils.crypto import get_random_string

import social_django.views
from social_django.utils import psa
from social_core.actions import do_auth,do_complete

from ipware.ip import get_client_ip
import json
import base64
import hashlib
import re
import traceback
import logging
from datetime import datetime
import urllib.parse
from pyotp.totp import TOTP

from . import models
from .cache import cache
from . import utils
from . import emails
from .exceptions import HttpResponseException

logger = logging.getLogger(__name__)
django_engine = engines['django']

#pre created succeed response,status = 200
SUCCEED_RESPONSE = HttpResponse(content='Succeed',status=200)

#pre created forbidden response, status = 403
FORBIDDEN_RESPONSE = HttpResponseForbidden()

#pre created conflict response, status=400
CONFLICT_RESPONSE = HttpResponse(content="Failed",status=409)

#pre creaed authentication required response, status=401
AUTH_REQUIRED_RESPONSE = HttpResponse(status=401)
AUTH_REQUIRED_RESPONSE.content = "Authentication required"

#pre creaed authentication not required response used by auth_optional,status = 204
AUTH_NOT_REQUIRED_RESPONSE = HttpResponse(content="Succeed",status=204)

#pre created basic auth required response,status = 401
BASIC_AUTH_REQUIRED_RESPONSE = HttpResponse(status=401)
BASIC_AUTH_REQUIRED_RESPONSE["WWW-Authenticate"] = 'Basic realm="Please login with your email address and access token"'
BASIC_AUTH_REQUIRED_RESPONSE.content = "Basic auth required"

def parse_basic(basic_auth):
    """
    Parse the basic header to a tuple(username,password)
    """
    if not basic_auth:
        raise Exception('Missing credentials')
    match = re.match('^Basic\\s+([a-zA-Z0-9+/=]+)$', basic_auth)
    if not match:
        raise Exception('Malformed Authorization header')
    basic_auth_raw = base64.b64decode(match.group(1)).decode('utf-8')
    if ':' not in basic_auth_raw:
        raise Exception('Missing password')
    return basic_auth_raw.split(":", 1)

NOT_AUTHORIZED_RESPONSE = HttpResponseForbidden()
def check_authorization(request,useremail):
    """
    Check whether the user(identified by email) has the permission to access the resource
    Return None if authorized;otherwise return forbidden response
    """
    #get the real request domain and request path from request header set in nginx if have;otherwise use the domain and path from http request
    domain = request.headers.get("x-upstream-server-name") or request.get_host()
    path = request.headers.get("x-upstream-request-uri") or request.path
    if path.startswith("/sso/"):
        #sso related request, should always be authorized.
        return None

    try:
        path = path[:path.index("?")]
    except:
        pass

    if models.can_access(useremail,domain,path):
        logger.debug("User({}) can access https://{}{}".format(useremail,domain,path))
        return None
    else:
        logger.debug("User({}) can't access https://{}{}".format(useremail,domain,path))
        return NOT_AUTHORIZED_RESPONSE


def get_post_logout_url(request,idp=None,encode=True):
    """
    Get post logout url, 
    The logout url is /sso/singedout, can have url parametgers
        relogin_url: the url to relogin
        idp: the idpid of the IdentiryProvider which is used for login
    params:
        request: the current http request
        idp: the currently used IdentiryProvider if have
        encode: encode the url if True;
    Return 	quoted post logout url
    """

    #get the real domain from request header set by nginx; if not found, use the request's domain
    host = request.headers.get("x-upstream-server-name") or request.get_host()
    #get the absolute signedout url
    post_logout_url = "https://{}/sso/signedout".format(host)

    #try to get relogin url from request url parameters
    relogin_url = request.GET.get("relogin_url")
    if not relogin_url:
        #not found in request url parameters, try to use the property 'next' from session as relogin url
        relogin_url = request.session.get("next")
        if not relogin_url:
            #still can't get the relogin url, use the home page of the domain as relogin url
            relogin_url = host

    if not relogin_url.startswith("https://"):
        #if relogin_url is not started with 'https://', add prefix 'https://'
        relogin_url = "https://{}".format(relogin_url)
         

    #get the idepid
    if idp:
        #parameter 'idp' is not None, the idpid directly.
        idpid = idp.idp
    else:
        #idp is not passed in, try to get the idp from session
        idpid = request.session.get("idp")

    if idpid:
        #if idpid is not None, encode it.
        idpid = urllib.parse.quote(idpid)

    if relogin_url:
        #if relogin_url is not None, encode it
        relogin_url = urllib.parse.quote(relogin_url)

    #add relogin_url and idpid as url parameters to post_logout_url
    params = None
    if relogin_url:
        params = "relogin_url={}".format(relogin_url)
        if idpid:
            params = "{}&idp={}".format(params,idpid)

    elif idpid:
        params = "idp={}".format(idpid)


    if params:
        backend_post_logout_url = "{}?{}".format(post_logout_url,params)
    else:
        backend_post_logout_url = post_logout_url

    #return econded or non-encoded post_logout_url based on parameter 'encode'
    return urllib.parse.quote(backend_post_logout_url) if encode else backend_post_logout_url

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
        'full_name' : "{}, {}".format(user.first_name,user.last_name),
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
    f_cache(cache_key,cached_response)
    logger.debug("cache the sso auth data for the user({}) with key({})".format(user.email,cache_key))

    return response

def _auth_prod(request):
    """
    has minimum logs, used in prod mode
    Authenticate and authorization the request; 
    If succeed,get the response from cache; if failed, populate one and cache it.
    Return
        None: not authenticated
        200 Response: authenticated and authorized
        403 Response: authenticated but not authorized.
    """
    if not request.user.is_authenticated:
        #not authenticated
        return None

    #authenticated
    #check authorization
    res = check_authorization(request,request.user.email)
    if res:
        #not authorized
        return res

    #authorized
    #get the reponse from cache
    user = request.user
    auth_key = cache.get_auth_key(user.email,request.session.session_key)
    response = cache.get_auth(auth_key,user.modified)

    if response:
        #response cached
        return response
    else:
        #reponse not cached, populate one and cache it.
        return _populate_response(request,cache.set_auth,auth_key,user,request.session.session_key)

def _auth_debug(request):
    """
    Has lots of logs,used in debug mode
    has the same logic as _auth_prod
    """
    start = timezone.now()
    
    logger.debug("==============Start to authenticate the user================")
    if not request.user.is_authenticated:
        #not authenticated
        diff = timezone.now() - start
        logger.debug("Spend {} milliseconds to find that user is not authenticated".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
        return None

    #authenticated
    diff = timezone.now() - start
    logger.debug("Spend {} milliseconds to find that user is authenticated".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
    before = timezone.now()

    #check authorization
    res = check_authorization(request,request.user.email)
    if res:
        #not authorized
        diff = timezone.now() - before
        logger.debug("Spend {} milliseconds to find that user is not authorized".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
        return res

    #authorized
    diff = timezone.now() - before
    logger.debug("Spend {} milliseconds to find that user is authorized".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
    before = timezone.now()

    #get the reponse from cache
    user = request.user
    auth_key = cache.get_auth_key(user.email,request.session.session_key)
    response = cache.get_auth(auth_key,user.modified)

    if response:
        #response cached
        diff = timezone.now() - before
        diff1 = timezone.now() - start
        logger.debug("Spend {} milliseconds to get the cached response,total spend {} milliseconds to process the request".format(round((diff.seconds * 1000 + diff.microseconds)/1000), round((diff1.seconds * 1000 + diff1.microseconds)/1000)))
        logger.debug("==============End to authenticate the user================")
        return response
    else:
        #response not cached; populate one and cache it
        diff = timezone.now() - before
        diff1 = timezone.now() - start
        logger.debug("Spend {} milliseconds to generate and cache the response, total spend {} milliseconds to process the request".format(round((diff.seconds * 1000 + diff.microseconds)/1000),round((diff1.seconds * 1000 + diff1.microseconds)/1000)))
        logger.debug("==============End to authenticate the user================")
        return _populate_response(request,cache.set_auth,auth_key,user,request.session.session_key)


#set autentication and authorization method to _auth_prod or _auth_debug based on running mode  
_auth = _auth_prod if settings.RELEASE else _auth_debug

@csrf_exempt
def auth(request):
    """
    view method for path '/sso/auth'
    Return
        200 reponse: authenticated and authorized
        401 response: not authenticated
        403 reponse: authenticated,but not authorized
    """
    res = _auth(request)
    if not res:
        #not authenticated
        return AUTH_REQUIRED_RESPONSE
    else:
        #authenticated, but can be authorized or not authorized
        return res

@csrf_exempt
def auth_optional(request):
    """
    view method for path '/sso/auth_optional'
    Return
        200 reponse: authenticated and authorized
        204 response: not authenticated
        403 reponse: authenticated,but not authorized
    """
    res = _auth(request)
    if not res:
        #not authenticated
        return AUTH_NOT_REQUIRED_RESPONSE
    else:
        #authenticated, but can be authorized or not authorized
        return res

@csrf_exempt
def auth_basic(request):
    """
    view method for path '/sso/auth_basic'
    First authenticate with username and user token; if failed,fall back to session authentication
    """
    #get the basic auth header
    auth_basic = request.META.get('HTTP_AUTHORIZATION').strip() if 'HTTP_AUTHORIZATION' in request.META else ''
    if not auth_basic:
        #not provide basic auth data
        #check whether session is already authenticated or not.
        res = _auth(request)
        if res:
            #already authenticated
            return res
        else:
            #not authenticated, return basic auth required response
            return BASIC_AUTH_REQUIRED_RESPONSE

    #get the user name and user toke by parsing the basic auth data
    username, token = parse_basic(auth_basic)

    #try to get the reponse from cache with username and token
    auth_basic_key = cache.get_basic_auth_key(username,token) 
    response= cache.get_basic_auth(auth_basic_key)
    if response:
        #found the cached reponse, already authenticated
        useremail = response['X-email']
        if settings.CHECK_AUTH_BASIC_PER_REQUEST:
            #check whehter user token is valid or not 
            #get the user object via useremail
            user = models.User.objects.get(email__iexact=useremail)
            if not user.token or not user.token.is_valid(token):
                #token is invalid, remove the cached response
                cache.delete_basic_auth(auth_basic_key)
                #fallback to session authentication
                res = _auth(request)
                if res:
                    #already authenticated, but can be authorized or not authorized
                    logger.debug("Failed to authenticate the user({}) with token, fall back to use session authentication".format(username))
                    return res
                else:
                    #not authenticated, return basic auth required reponse
                    logger.debug("Failed to authenticate the user({}) with token".format(username))
                    return BASIC_AUTH_REQUIRED_RESPONSE
            
            #token is valid
            useremail = user.email

        request.session.modified = False
        #check authorization    
        res = check_authorization(request,useremail)
        if res:
            #not authorized
            return res
        else:
            #authorized
            return response
    else:
        #not found the cached reponse, not authenticated before.
        try:
            if "@" in username:
                #username is an email address, get the user via email
                user = models.User.objects.get(email__iexact=username)
            else:
                #username is not an email address, get the user via username
                #but current, username is equal with email address. so this logic will not be hit.
                user = models.User.objects.filter(username__iexact=username).first()
                if not user:
                    logger.debug("User({}) doesn't exist".format(username))
                    return BASIC_AUTH_REQUIRED_RESPONSE

            if request.user.is_authenticated and user.email == request.user.email:
                #the user of the token auth is the same user as the authenticated session user;use the session authentication data directly
                return _auth(request)

            #user session is not authenticated or the user of the user token is not the same user as the authenticated sesion user.
            #check whther user token is valid
            if user.token and user.token.is_valid(token):
                #user token is valid, authenticated
                logger.debug("Succeed to authenticate the user({}) with token".format(username))
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
            else:
                #user token is invalid; fallback to user session authentication
                res = _auth(request)
                if res:
                    #already authenticated,but can authorized or not authorized
                    logger.debug("Failed to authenticate the user({}) with token, fall back to use session authentication".format(username))
                    return res
                else:
                    #Not authenticated, return basic auth required response
                    logger.debug("Failed to authenticate the user({}) with token".format(username))
                    return BASIC_AUTH_REQUIRED_RESPONSE

        except Exception as e:
            #return basi auth required response if any exception occured.
            return BASIC_AUTH_REQUIRED_RESPONSE


def logout_view(request):
    """
    View method for path '/sso/auth_logout'
    """
    #get backend logout url
    backend_logout_url = request.session.get("backend_logout_url")
    #get post logout url
    post_logout_url = get_post_logout_url(request,encode=False)
    #logout the django user session
    logout(request)
    #redirect to backend to logout backend
    if backend_logout_url:
        return HttpResponseRedirect(backend_logout_url.format(urllib.parse.quote(post_logout_url)))
    elif settings.BACKEND_LOGOUT_URL:
        return HttpResponseRedirect(settings.BACKEND_LOGOUT_URL.format(urllib.parse.quote(post_logout_url)))
    else:
        return HttpResponseRedirect(post_logout_url)

def home(request):
    """
    View method for path '/'
    redirect to next url if authenticated and authorized; 
    redirect to '/sso/forbidden' if authenticated but not authorized
    Trigger authentication user flow if not authenticated
    """
    next_url = request.GET.get('next', None)
    #check whether rquest is authenticated and authorized
    if not request.user.is_authenticated:
        #not authenticated
        #get authenticatation url
        url = reverse('social:begin', args=['azuread-b2c-oauth2'])
        if next_url:
            #has next_url, add next url to authentication url as url parameter
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
        #authenticated and authorized
        if next_url:
            #has next_url, redirect to that url
            if next_url.startswith("http"):
                return HttpResponseRedirect(next_url)
            else:
                return HttpResponseRedirect('https://{}'.format(next_url))
        else:
            #no next url, return user profile.
            return profile(request)

def loginstatus(request):
    """
    View method for path '/sso/loginstatus'
    Return a page to indicate the login status
    """
    res = _auth(request)

    return TemplateResponse(request,"authome/loginstatus.html",context={"message":"You {} logged in".format("are" if res else "aren't")})


@login_required
@csrf_exempt
def profile(request):
    """
    View method for path '/sso/profile'
    Must called after authentication
    Return the authenticated user profile as json
    """
    #get the auth response
    user = request.user
    auth_key = cache.get_auth_key(user.email,request.session.session_key)
    response = cache.get_auth(auth_key,user.modified)

    if not response:
        response = _populate_response(request,cache.set_auth,auth_key,user,request.session.session_key)

    #populte the profile from response headers
    content = {}
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
            content["access_token_error"] = "Access token is created, please ask administrator to create"
        elif token.is_expired:
            content["access_token"] = token.token
            content["access_token_created"] = timezone.localtime(token.created).strftime("%Y-%m-%d %H:%M:%S")
            content["access_token_expired"] = token.expired.strftime("%Y-%m-%d")
            content["access_token_error"] = "Access token is expired, please ask administroator to recreate"
        else:
            content["access_token"] = token.token
            content["access_token_created"] = timezone.localtime(token.created).strftime("%Y-%m-%d %H:%M:%S")
            if token.expired:
                content["access_token_expired"] = token.expired.strftime("%Y-%m-%d 23:59:59")
    except Exception as ex:
        logger.error("Failed to get access token for the user({}).{}".format(user.email,traceback.format_exc()))
        content["access_token_error"] = str(ex)
        
    content = json.dumps(content)
    return HttpResponse(content=content,content_type="application/json")

"""
API_VERSION = "0.0.1"
@csrf_exempt
def check_signup(request):
    body = {"version": API_VERSION}
    try:
        request_body = json.loads(request.body.decode())
        logger.debug("signup data is '{}'".format(request_body))
        email = request_body.get("email",None)
        body = {"version": API_VERSION}
        status_code = 200
        if not email :
            body["action"] = "ValidationError"
            body["userMessage"] = "User Email is empty"
            status_code = 400
        elif "@" not in email:
            body["action"] = "ValidationError"
            body["userMessage"] = "User Email is empty"
            status_code = 400
        elif models.UserGroup.dbca_group().contain(email):
            status_code = 200
            body["action"] = "Continue"
        else:
            users = models.User.objects.filter(email__iexact=email)
            if len(users) == 1:
                user = users[0]
                update_fields = []
                for col,prop in [("first_name","givenName"),("last_name","surname")]:
                    val = request_body.get(prop,None)
                    if val and val != getattr(user,col):
                        setattr(user,col,val)
                        update_fields.append(col)
                if update_fields:
                    user.save(update_fields=update_fields)
                status_code = 200
                body["action"] = "Continue"
            elif len(users) > 1:
                status_code = 200
                body["action"] = "ShowBlockPage"
                body["userMessage"] = "You are registered multiple times. Please ask dbca admin to register you properly before you can sign-up"
            else:
                status_code = 200
                body["action"] = "ShowBlockPage"
                body["userMessage"] = "Please ask dbca admin to register you first before you can sign-up"
    except Exception as ex:
        logger.error("Failed to check user sign-up.{}".format(traceback.format_exc()))
        status_code = 200
        body["action"] = "ShowBlockPage"
        body["userMessage"] = "Failed to check user sign-up with error {}".format(str(ex))

    return JsonResponse(body,status=status_code)
"""

@csrf_exempt
def signedout(request):
    """
    View method for path '/sso/signedout'
    Return a consistent signedout page
    """
    #get the real domain from request header set by nginx;if not found, use request's domain
    domain = request.headers.get("x-upstream-server-name") or request.get_host()
    if request.user.is_authenticated:
        #still authenticated, redirect to path '/sso/auth_logout' to trigger an logout flow
        return HttpResponseRedirect("https://{}/sso/auth_logout".format(domain))

    #get the relogin_url from request url parameters
    relogin_url = request.GET.get("relogin_url")
    if not relogin_url:
        #can't the the relogin url, use the domain's home page as relogin url
        relogin_url = "https://{}".format(domain)

    #get idp to trigger a backend logout flow
    idpid = request.GET.get("idp")
    idp = models.IdentityProvider.get_idp(idpid)

    context = {
        "relogin_url":relogin_url
    }
    if idp and idp.logout_url:
        context["idp_name"] = idp.name
        context["idp_logout_url"] = idp.logout_url
    content = django_engine.get_template("authome/inc/signedout.html").render(
        context=context,
        request=request
    )
    container_class = "content_container"
    userflow = models.CustomizableUserflow.get_userflow(domain)
    _init_userflow_pagelayout(request,userflow,container_class)

    page_layout = getattr(userflow,container_class)
    extracss = userflow.inited_extracss

    context = {"body":page_layout,"extracss":extracss,"content":content,"title":"You are signed out."}
    if domain:
        context["domain"] = domain

    return TemplateResponse(request,"authome/default.html",context=context)

def signout(request,**kwargs):
    """
    Called by pipeline to automatically logout the user beceause some errors occured druing authentication.
    """
    if kwargs.get("message"):
        #has error message, return a page to show the message and let the user trigger the logout flow 
        kwargs["auto_signout_delay_seconds"] = settings.AUTO_SIGNOUT_DELAY_SECONDS
        return TemplateResponse(request,"authome/signout.html",context=kwargs)
    else:
        #no error message,automatically trigger the logout flow
        return HttpResponseRedirect(kwargs["logout_url"])

def _init_userflow_pagelayout(request,userflow,container_class):
    """
    Initialize the pagelayout for the custmizable userflow and container_class
    """
    if hasattr(userflow,container_class):
        #already initialized
        return

    #initialize the page layout for the user userflow and container class
    if not userflow.page_layout:
        #page_layout is not configured, use parent's page_layout
        #initialize parent,
        _init_userflow_pagelayout(request,userflow.parent,container_class)
        #set userflow's page layout to default userflow's page layout
        setattr(userflow,container_class,getattr(userflow.parent,container_class))
        userflow.inited_extracss = userflow.parent.inited_extracss
    else:
        #page_layout is configured, init page_layout using template engine
        context={"container_class":container_class}
        page_layout = userflow.page_layout
    
        page_layout = django_engine.from_string(page_layout).render(
            context=context,
            request=request
        )
        setattr(userflow,container_class,page_layout)
    
        if not hasattr(userflow,"inited_extracss"):
            #init extracss using template engine
            extracss = userflow.extracss or ""
            userflow.inited_extracss = django_engine.from_string(extracss).render(
                context=context,
                request=request
            )


def _init_userflow_verifyemail(request,userflow):
    """
    Initialize the verifyemail for customizable userflow object
    """
    if hasattr(userflow,"verifyemail_body_template"):
        #already initialized
        return

    #initialize verifyemail related properties
    if not userflow.verifyemail_from:
        #verifyemail_from is not configured, get it from default userflow
        _init_userflow_verifyemail(request,userflow.parent)
        userflow.verifyemail_from = userflow.parent.verifyemail_from

    if not userflow.verifyemail_subject:
        #verifyemail_subject is not configured, get it from default userflow
        _init_userflow_verifyemail(request,userflow.parent)
        userflow.verifyemail_subject = userflow.parent.verifyemail_subject

    if userflow.verifyemail_body:
        #verifyemail_body is configured, get it from template
        userflow.verifyemail_body_template = django_engine.from_string(userflow.verifyemail_body)
    else:
        #verifyemail_body is not configured, get it from default userflow
        _init_userflow_verifyemail(request,userflow.parent)
        userflow.verifyemail_body_template = userflow.parent.verifyemail_body_template

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
    if not container_class:
        container_class = "{}_container".format(template)
    title = request.GET.get('title', "Signup or Signin")
    userflow = models.CustomizableUserflow.get_userflow(domain)

    _init_userflow_pagelayout(request,userflow,container_class)

    page_layout = getattr(userflow,container_class)
    extracss = userflow.inited_extracss

    context = {"body":page_layout,"extracss":extracss,"title":title}
    if domain:
        context["domain"] = domain

    return TemplateResponse(request,"authome/{}.html".format(template),context=context)

def forbidden(request):
    """
    View method for path '/sso/forbidden'
    Provide a consistent,customized forbidden page.
    """
    context = {}
    domain = request.headers.get("x-upstream-server-name") or request.get_host()
    path = request.headers.get("x-upstream-request-uri") or request.path
    context["domain"] = domain
    context["path"] = path
    context["url"] = "https://{}{}".format(domain,path)
    logger.debug("forbidden context = {}".format(context))

    content = django_engine.get_template("authome/inc/forbidden.html").render(
        context=context,
        request=request
    )
    container_class = "content_container"
    userflow = models.CustomizableUserflow.get_userflow(domain)
    _init_userflow_pagelayout(request,userflow,container_class)

    page_layout = getattr(userflow,container_class)
    extracss = userflow.inited_extracss

    context = {"body":page_layout,"extracss":extracss,"content":content,"title":"Access denied"}
    if domain:
        context["domain"] = domain

    return TemplateResponse(request,"authome/default.html",context=context)


@never_cache
@psa("/sso/profile/edit/complete")
def profile_edit(request,backend):
    """
    View method for path '/sso/profile/edit'
    Start a profile edit user flow
    called after user authentication
    """
    if request.GET.get(REDIRECT_FIELD_NAME):
        logger.debug("Found next url '{}'".format(request.GET.get(REDIRECT_FIELD_NAME)))
        pass
    else:
        request.session[REDIRECT_FIELD_NAME] = "https://{}/sso/profile".format(utils.get_request_domain(request))
        logger.debug("No next url provided,set the next url to '{}'".format(request.session[REDIRECT_FIELD_NAME]))

    domain = utils.get_redirect_domain(request)
    request.policy = models.CustomizableUserflow.get_userflow(domain).profile_edit
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)


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
    domain = utils.get_redirect_domain(request)
    request.policy = models.CustomizableUserflow.get_userflow(domain).profile_edit
    request.http_error_code = 417
    request.http_error_message = "Failed to edit user profile.{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)

"""
@never_cache
@psa("/sso/email/signup/complete")
def email_signup(request,backend):
    domain = utils.get_redirect_domain(request)
    request.policy = models.CustomizableUserflow.get_userflow(domain).email_signup
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)

@never_cache
@csrf_exempt
@psa("/sso/email/signup/complete")
def email_signup_complete(request,backend,*args,**kwargs):
    domain = utils.get_redirect_domain(request)
    request.policy = models.CustomizableUserflow.get_userflow(domain).email_signup
    request.http_error_code = 417
    request.http_error_message = "Failed to signup a local account..{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)
"""                       

@never_cache
@psa("/sso/password/reset/complete")
def password_reset(request,backend):
    """
    View method for path '/sso/password/reset'
    Start a password reset user flow
    Triggered by hyperlink 'Forgot your password' in idp selection page
    """
    domain = utils.get_redirect_domain(request)
    request.policy = models.CustomizableUserflow.get_userflow(domain).password_reset
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)

@never_cache
@csrf_exempt
@psa("/sso/password/reset/complete")
def password_reset_complete(request,backend,*args,**kwargs):
    """
    View method for path '/sso/password/reset/complete'
    Callback url from b2c to complete a user password reset request
    """
    domain = utils.get_redirect_domain(request)
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
    domain = utils.get_redirect_domain(request)
    request.policy = models.CustomizableUserflow.get_userflow(domain).mfa_set
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)

@never_cache
@csrf_exempt
@psa("/sso/mfa/set/complete")
def mfa_set_complete(request,backend,*args,**kwargs):
    """
    View method for path '/sso/mfa/set/complete'
    Callback url from b2c to complete a user mfa set request
    """
    domain = utils.get_redirect_domain(request)
    request.policy = models.CustomizableUserflow.get_userflow(domain).mfa_set
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
        return FORBIDDEN_RESPONSE

    #get the domain from request url parameters
    domain = request.GET.get('domain', None)
    #get domain related userflow
    userflow = models.CustomizableUserflow.get_userflow(domain)
    #initialized the userflow if required
    _init_userflow_verifyemail(request,userflow)

    data = json.loads(request.body.decode())

    #get the verificatio email body
    verifyemail_body = userflow.verifyemail_body_template.render(
        context=data,
        request=request
    )
    #send email
    emails.send_email(userflow.verifyemail_from,data["email"],userflow.verifyemail_subject,verifyemail_body)
    logger.debug("Successfully send verification email to '{}',domain is '{}'".format(data["email"],domain))
    return SUCCEED_RESPONSE

user_totp_key_chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
@never_cache
@csrf_exempt
def totp_generate(request):
    """
    View method for path '/sso/totp/generate'
    The idp should exist and have a meaningful name, otherwise, a 400 response will be returned.
    """
    #authenticate the request
    if not _auth_bearer(request):
        #not authenticated
        return FORBIDDEN_RESPONSE

    #get the user email and idp
    data = json.loads(request.body.decode())
    user_email = data.get("email")
    if not user_email:
        logger.debug("Email is missing")
        return HttpResponse(content="Email is missing",status=400)

    idp = data.get("idp")
    if not idp:
        logger.debug("IDP is missing")
        return HttpResponse(content="Idp is missing",status=400)
    elif idp.startswith("local_"):
        #all idps with prefx "local_" is local account identity provider
        idp = "local"

    idp_obj = models.IdentityProvider.get_idp(idp)
    if not idp_obj:
        logger.debug("Idp{} Not Found".format(idp))
        return HttpResponse(content="Idp{} Not Found".format(idp),status=400)
    elif not idp_obj.name:
        logger.debug("The name of the idp{} is missing".format(idp))
        return HttpResponse(content="The name of the idp{} is missing".format(idp),status=400)

    #regenerate flag, currently it is not used in custom policy
    regenerate = data.get("regenerate",False)

    #get the user totp object
    user_totp = models.UserTOTP.objects.filter(email=user_email,idp=idp).first()
    if not user_totp or regenerate:
        #not exist or require regenerating again
        #generate a new code
        if not user_totp:
            user_totp = models.UserTOTP(email=user_email,idp=idp)
        user_totp.secret_key = base64.b32encode(bytearray(get_random_string(settings.TOTP_SECRET_KEY_LENGTH,user_totp_key_chars),'ascii')).decode()
        user_totp.timestep = settings.TOTP_TIMESTEP
        user_totp.issuer = settings.TOTP_ISSUER
        user_totp.name = "{}({})".format(user_email,idp_obj.name)
        user_totp.prefix = settings.TOTP_PREFIX or settings.TOTP_ISSUER
        user_totp.digits = settings.TOTP_DIGITS
        user_totp.algorithm = settings.TOTP_ALGORITHM
        user_totp.created = timezone.now()
        user_totp.verified = None
        user_totp.last_verified_code = None

        user_totp.save()
     
    #get the totp url
    totpurl = utils.get_totpurl(user_totp.secret_key,user_totp.name,user_totp.issuer,user_totp.timestep,user_totp.prefix,algorithm=user_totp.algorithm,digits=user_totp.digits)
    #generate the qrcode and encode it as base64 string
    qrcode = utils.encode_qrcode(totpurl)

    data = {
        "qrCode" : qrcode
    }
    
    return JsonResponse(data,status=200)


@never_cache
@csrf_exempt
def totp_verify(request):
    """
    View method for path '/sso/totp/verify'
    """
    #authenticate the request
    if not _auth_bearer(request):
        #not authenticated
        return FORBIDDEN_RESPONSE

    #get the useremail, idp and totpcode
    data = json.loads(request.body.decode())
    logger.debug("verify totp code.{}".format(data))
    user_email = data.get("email")
    if not user_email:
        return HttpResponse(content="Email is missint",status=400)

    idp = data.get("idp")
    if not idp:
        return HttpResponse(content="Idp is missint",status=400)

    totpcode = data.get("totpCode")
    if not totpcode:
        return HttpResponse(content="Totp code is missint",status=400)

    user_totp = models.UserTOTP.objects.filter(email=user_email,idp=idp).first()
    if not user_totp :
        #can't find user totp object
        return HttpResponse(content="User({1}:{0})'s totp secret is missing".format(user_email,idp),status=400)

    if settings.TOTP_CHECK_LAST_CODE and totpcode == user_totp.last_verified_code:
        #totpcode is the last checked totp code,
        return CONFLICT_RESPONSE 
        
    totp = TOTP(user_totp.secret_key,digits=user_totp.digits,digest=utils.get_digest_function(user_totp.algorithm)[1],name=user_totp.name,issuer=user_totp.issuer,interval=user_totp.timestep)
    if totp.verify(totpcode,valid_window=settings.TOTP_VALIDWINDOW):
        #verified
        user_totp.last_verified_code = totpcode
        user_totp.last_verified = timezone.now()
        user_totp.save(update_fields=["last_verified","last_verified_code"])
        logger.debug("Succeed to verify totp code.{}".format(data))
        return SUCCEED_RESPONSE
    else:
        #verify failed.
        logger.debug("Failed to verify totp code.{}".format(data))
        return CONFLICT_RESPONSE 

def handler400(request,exception,**kwargs):
    """
    Customizable handler to process 400 response.
    This method provide a hook to let exception return its own response
    """
    if isinstance(exception,HttpResponseException):
        res = exception.get_response(request)
        if res:
            return res

    domain = request.headers.get("x-upstream-server-name") or utils.get_redirect_domain(request) or request.get_host()
    content = django_engine.get_template("authome/inc/error.html").render(
        context={"message":str(exception)},
        request=request
    )
    container_class = "content_container"
    userflow = models.CustomizableUserflow.get_userflow(domain)
    _init_userflow_pagelayout(request,userflow,container_class)

    page_layout = getattr(userflow,container_class)
    extracss = userflow.inited_extracss

    context = {"body":page_layout,"extracss":extracss,"content":content,"title":"Authentication failed."}
    if domain:
        context["domain"] = domain

    code = exception.http_code or 400
    return TemplateResponse(request,"authome/default.html",context=context,status=code)
  
