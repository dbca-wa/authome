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

from django.contrib.auth.models import User
from .models import can_access,UserToken,UserGroup,IdentityProvider,User,CustomizableUserflow
from .cache import cache
from .utils import get_clientapp_domain,get_domain

logger = logging.getLogger(__name__)
django_engine = engines['django']

def parse_basic(basic_auth):
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
    Return None if authorized;otherwise return Authorized failed response
    """
    domain = request.headers.get("x-upstream-server-name") or request.get_host()
    path = request.headers.get("x-upstream-request-uri") or request.path
    try:
        path = path[:path.index("?")]
    except:
        pass

    if can_access(useremail,domain,path):
        logger.debug("User({}) can access https://{}{}".format(useremail,domain,path))
        return None
    else:
        logger.debug("User({}) can't access https://{}{}".format(useremail,domain,path))
        return NOT_AUTHORIZED_RESPONSE


def _populate_response(request,f_cache,cache_key,user,session_key=None):
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

    response = HttpResponse(content="Succeed")
    cached_response = HttpResponse(content="Succeed")
    for key, val in headers.items():
        key = "X-" + key.replace("_", "-")
        response[key] = val
        cached_response[key] = val

    cached_response["X-auth-cache-hit"] = "success"
    response["remote-user"] = user.email
    cached_response["remote-user"] = user.email
    # cache authentication entries
    f_cache(cache_key,cached_response)
    logger.debug("cache the sso auth data for the user({}) with key({})".format(user.email,cache_key))

    return response

def _auth_prod(request):
    if not request.user.is_authenticated:
        return None

    res = check_authorization(request,request.user.email)
    if res:
        #user has no permission to access this url
        return res

    user = request.user
    auth_key = cache.get_auth_key(user.email,request.session.session_key)
    response = cache.get_auth(auth_key,user.modified)

    if response:
        return response
    else:
        return _populate_response(request,cache.set_auth,auth_key,user,request.session.session_key)

def _auth_debug(request):
    start = timezone.now()
    
    logger.debug("==============Start to authenticate the user================")
    if not request.user.is_authenticated:
        diff = timezone.now() - start
        logger.debug("Spend {} milliseconds to find that user is not authenticated".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
        return None

    diff = timezone.now() - start
    logger.debug("Spend {} milliseconds to find that user is authenticated".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
    before = timezone.now()

    res = check_authorization(request,request.user.email)
    if res:
        #user has no permission to access this url
        diff = timezone.now() - before
        logger.debug("Spend {} milliseconds to find that user is not authorized".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
        return res

    diff = timezone.now() - before
    logger.debug("Spend {} milliseconds to find that user is authorized".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
    before = timezone.now()

    user = request.user
    auth_key = cache.get_auth_key(user.email,request.session.session_key)
    response = cache.get_auth(auth_key,user.modified)

    if response:
        diff = timezone.now() - before
        diff1 = timezone.now() - start
        logger.debug("Spend {} milliseconds to get the cached response,total spend {} milliseconds to process the request".format(round((diff.seconds * 1000 + diff.microseconds)/1000), round((diff1.seconds * 1000 + diff1.microseconds)/1000)))
        logger.debug("==============End to authenticate the user================")
        return response
    else:
        diff = timezone.now() - before
        diff1 = timezone.now() - start
        logger.debug("Spend {} milliseconds to generate and cache the response, total spend {} milliseconds to process the request".format(round((diff.seconds * 1000 + diff.microseconds)/1000),round((diff1.seconds * 1000 + diff1.microseconds)/1000)))
        logger.debug("==============End to authenticate the user================")
        return _populate_response(request,cache.set_auth,auth_key,user,request.session.session_key)


AUTH_REQUIRED_RESPONSE = HttpResponse(status=401)
AUTH_REQUIRED_RESPONSE.content = "Authentication required"

_auth = _auth_prod if settings.RELEASE else _auth_debug

AUTH_NOT_REQUIRED_RESPONSE = HttpResponse(content="Succeed",status=204)
@csrf_exempt
def auth(request):
    res = _auth(request)
    if not res:
        return AUTH_REQUIRED_RESPONSE
    else:
        return res

@csrf_exempt
def auth_optional(request):
    res = _auth(request)
    if not res:
        return AUTH_NOT_REQUIRED_RESPONSE
    else:
        return res

BASIC_AUTH_REQUIRED_RESPONSE = HttpResponse(status=401)
BASIC_AUTH_REQUIRED_RESPONSE["WWW-Authenticate"] = 'Basic realm="Please login with your email address and access token"'
BASIC_AUTH_REQUIRED_RESPONSE.content = "Basic auth required"

@csrf_exempt
def auth_basic(request):
    """
    First authenticate the token and then fall back to session authentication
    """
    auth_basic = request.META.get('HTTP_AUTHORIZATION').strip() if 'HTTP_AUTHORIZATION' in request.META else ''
    if not auth_basic:
        #not provide basic auth data,check whether session is already authenticated or not.
        res = _auth(request)
        if res:
            #already authenticated
            return res
        else:
            #require the user to provide credential using basic auth
            return BASIC_AUTH_REQUIRED_RESPONSE

    username, token = parse_basic(auth_basic)

    auth_basic_key = cache.get_basic_auth_key(username,token) 
    response= cache.get_basic_auth(auth_basic_key)
    if response:
        #already authenticated with token auth data, using the token auth data instead of current session authentication data (if have)
        useremail = response['X-email']
        if settings.CHECK_AUTH_BASIC_PER_REQUEST:
            user = User.objects.get(email__iexact=useremail)
            if not user.token or not user.token.is_valid(token):
                #token is invalid, fallback to session authentication
                cache.delete_basic_auth(auth_basic_key)
                res = _auth(request)
                if res:
                    #already authenticated
                    logger.debug("Failed to authenticate the user({}) with token, fall back to use session authentication".format(username))
                    return res
                else:
                    #require the user to provide credential using basic auth
                    logger.debug("Failed to authenticate the user({}) with token".format(username))
                    return BASIC_AUTH_REQUIRED_RESPONSE

            useremail = user.email

        request.session.modified = False
            
        res = check_authorization(request,useremail)
        if res:
            #not authorized
            return res
        else:
            return response
    else:
        try:
            if "@" in username:
                user = User.objects.get(email__iexact=username)
            else:
                user = User.objects.filter(username__iexact=username).first()
                if not user:
                    logger.debug("User({}) doesn't exist".format(username))
                    return BASIC_AUTH_REQUIRED_RESPONSE

            if request.user.is_authenticated and user.email == request.user.email:
                #the user of the token auth is the same as the authenticated session user;use the session authentication data directly
                return _auth(request)

            if user.token and user.token.is_valid(token):
                logger.debug("Succeed to authenticate the user({}) with token".format(username))
                request.user = user
                request.session.modified = False

                response = _populate_response(request,cache.set_basic_auth,auth_basic_key,user)
                res = check_authorization(request,user.email)
                if res:
                    return res
                else:
                    return response
            else:
                res = _auth(request)
                if res:
                    #already authenticated
                    logger.debug("Failed to authenticate the user({}) with token, fall back to use session authentication".format(username))
                    return res
                else:
                    #require the user to provide credential using basic auth
                    logger.debug("Failed to authenticate the user({}) with token".format(username))
                    return BASIC_AUTH_REQUIRED_RESPONSE

        except Exception as e:
            return BASIC_AUTH_REQUIRED_RESPONSE


def logout_view(request):
    backend_logout_url = request.session.get("backend_logout_url")
    post_logout_url = get_post_logout_url(request,encode=False)
    logout(request)
    if backend_logout_url:
        return HttpResponseRedirect(backend_logout_url.format(urllib.parse.quote(post_logout_url)))
    elif settings.BACKEND_LOGOUT_URL:
        return HttpResponseRedirect(settings.BACKEND_LOGOUT_URL.format(urllib.parse.quote(post_logout_url)))
    else:
        return HttpResponseRedirect(post_logout_url)

def home(request):
    next_url = request.GET.get('next', None)
    res = _auth(request)
    if not res:
        url = reverse('social:begin', args=['azuread-b2c-oauth2'])
        if next_url:
            url += '?{}'.format(urlencode({'next': next_url}))
        else:
            #clean the next url  from session
            try:
                del request.session[REDIRECT_FIELD_NAME]
            except:
                pass
        logger.debug("sso auth url = {}".format(url))
        res = HttpResponseRedirect(url)
        return res
    elif next_url:
        return HttpResponseRedirect('https://{}'.format(next_url))
    else:
        if res.status_code >= 400:
            return TemplateResponse(request,"authome/loginstatus.html",context={"message":"You are not authorized"})
        else:
            return profile(request)

def loginstatus(request):
    res = _auth(request)

    return TemplateResponse(request,"authome/loginstatus.html",context={"message":"You {} logged in".format("are" if res else "aren't")})


@login_required
@csrf_exempt
def profile(request):
    user = request.user
    auth_key = cache.get_auth_key(user.email,request.session.session_key)
    response = cache.get_auth(auth_key,user.modified)

    if not response:
        response = _populate_response(request,cache.set_auth,auth_key,user,request.session.session_key)

    content = {}
    for key,value in response.items():
        if key.startswith("X-"):
            key = key[2:].replace("-","_")
            content[key] = value

    current_ip,routable = get_client_ip(request)
    content['client_logon_ip'] = current_ip
    try:
        token = UserToken.objects.filter(user = user).first()
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
        elif UserGroup.dbca_group().contain(email):
            status_code = 200
            body["action"] = "Continue"
        else:
            users = User.objects.filter(email__iexact=email)
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


@csrf_exempt
def signedout(request):
    if request.user.is_authenticated:
        host = request.headers.get("x-upstream-server-name") or request.get_host()
        return HttpResponseRedirect("https://{}/sso/auth_logout".format(host))
    return TemplateResponse(request,"authome/signedout.html")

def signout(request,**kwargs):
    if kwargs.get("message"):
        kwargs["auto_signout_delay_seconds"] = settings.AUTO_SIGNOUT_DELAY_SECONDS
        return TemplateResponse(request,"authome/signout.html",context=kwargs)
    else:
        return HttpResponseRedirect(kwargs["logout_url"])

login_js_template = """
<script type="text/javascript">
var createAccount = document.getElementById("createAccount")
var forgotPassword = document.getElementById("forgotPassword")
if (createAccount && forgotPassword){
    createAccount.href = "{{email_signup_url}}"
    forgotPassword.href = "{{password_reset_url}}"
} 
// Select the node that will be observed for mutations
const targetNode = document.getElementById('api');

// Options for the observer (which mutations to observe)
const config = {  childList: true, subtree: true,attributes:true };

// Callback function to execute when mutations are observed
const callback = function(mutationsList, observer) {
    createAccount = document.getElementById("createAccount")
    forgotPassword = document.getElementById("forgotPassword")
    if (createAccount && forgotPassword){
        observer.disconnect();
        createAccount.href = "{{email_signup_url}}"
        forgotPassword.href = "{{password_reset_url}}"
        observer.observe(targetNode, config);
    }
}
// Create an observer instance linked to the callback function
const observer = new MutationObserver(callback);
// Start observing the target node for configured mutations
observer.observe(targetNode, config);
</script>
"""

login_js = None
context = None
def _init_userflow(request,userflow):
    if userflow.initialized:
        #already initialized
        return

    #initialize the user userflow
    global context
    if not context:
        context={"email_signup_url":request.build_absolute_uri(reverse("email_signup")),'password_reset_url':request.build_absolute_uri(reverse("password_reset"))}

    #initialize the user userflow
    if not userflow.page_layout:
        #userflow has no customized page_layout, use the defaultuserflow's page_layout
        #initialize defaultuserflow,
        _init_userflow(request,userflow.defaultuserflow)
        #set userflow's page layout to default userflow's page layout
        userflow.page_layout = userflow.defaultuserflow.page_layout
        if userflow.email_enabled:
            userflow.loginpage_layout = userflow.defaultuserflow.page_layout_with_js
        else:
            userflow.loginpage_layout = userflow.defaultuserflow.page_layout
        userflow.extracss = userflow.defaultuserflow.extracss
        userflow.initialized = True
    else:
        page_layout = userflow.page_layout
    
        page_layout = django_engine.from_string(page_layout).render(
            context=context,
            request=request
        )
        userflow.page_layout = page_layout
        #init login page layout
        if userflow.is_default or userflow.email_enabled:
            global login_js
            if not login_js:
                login_js = django_engine.from_string(login_js_template).render(
                    context=context,
                    request=request
                )
            page_layout_with_js = "{}{}".format(page_layout,login_js)

            if userflow.is_default:
                userflow.page_layout_with_js = page_layout_with_js
            if userflow.email_enabled:
                userflow.loginpage_layout = page_layout_with_js
            else:
                userflow.loginpage_layout = page_layout
        else:
            userflow.loginpage_layout = page_layout
    
        #init extracss
        extracss = userflow.extracss or ""
        extracss = django_engine.from_string(extracss).render(
            context=context,
            request=request
        )
        userflow.extracss = extracss
    
        userflow.initialized = True

def adb2c_view(request,template,**kwargs):
    domain = request.GET.get('domain', None)
    userflow = CustomizableUserflow.get_userflow(domain)

    _init_userflow(request,userflow)

    if template == "login":
        page_layout = userflow.loginpage_layout
    else:
        page_layout = userflow.page_layout

    extracss = userflow.extracss

    return TemplateResponse(request,"authome/{}.html".format(template),context={"body":page_layout,"extracss":extracss})

def forbidden(request):
    context = {}
    domain = request.headers.get("x-upstream-server-name") or request.get_host()
    path = request.headers.get("x-upstream-request-uri") or request.path
    context["domain"] = domain
    context["path"] = path
    context["url"] = "https://{}{}".format(domain,path)
    print("forbidden context = {}".format(context))
    return TemplateResponse(request,"authome/forbidden.html",context=context)

def get_post_logout_url(request,idp=None,encode=True):
    """
    Return 	quoted post logout url
    """
    host = request.headers.get("x-upstream-server-name") or request.get_host()
    post_logout_url = "https://{}/sso/signedout".format(host)
    idp_logout_url = idp.logout_url if idp else IdentityProvider.get_logout_url(request.session.get("idp"))

    if idp_logout_url:
        backend_post_logout_url = idp_logout_url.format(post_logout_url)
    else:
        backend_post_logout_url = post_logout_url

    return urllib.parse.quote(backend_post_logout_url) if encode else backend_post_logout_url

@never_cache
@psa("/sso/profile/edit/complete")
def profile_edit(request,backend):
    domain = get_clientapp_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).profile_edit
    if not request.GET.get(REDIRECT_FIELD_NAME):
        request.session[REDIRECT_FIELD_NAME] = "https://{}/sso/profile".format(get_clientapp_domain(request))
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)


def _do_login(*args,**kwargs):
    pass

@never_cache
@csrf_exempt
@psa("/sso/profile/edit/complete")
def profile_edit_complete(request,backend,*args,**kwargs):
    domain = get_clientapp_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).profile_edit
    request.http_error_code = 417
    request.http_error_message = "Failed to edit user profile.{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)


@never_cache
@psa("/sso/email/signup/complete")
def email_signup(request,backend):
    domain = get_clientapp_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).email_signup
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)

@never_cache
@csrf_exempt
@psa("/sso/email/signup/complete")
def email_signup_complete(request,backend,*args,**kwargs):
    domain = get_clientapp_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).email_signup
    request.http_error_code = 417
    request.http_error_message = "Failed to signup a local account..{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)

@never_cache
@psa("/sso/password/reset/complete")
def password_reset(request,backend):
    domain = get_clientapp_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).password_reset
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)

@never_cache
@csrf_exempt
@psa("/sso/password/reset/complete")
def password_reset_complete(request,backend,*args,**kwargs):
    domain = get_clientapp_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).password_reset
    request.http_error_code = 417
    request.http_error_message = "Failed to reset password..{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)

