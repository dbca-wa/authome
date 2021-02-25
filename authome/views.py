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

from django.contrib.auth.models import User
from .models import can_access,UserToken,UserGroup,IdentityProvider,User,CustomizableUserflow
from .cache import cache
from .utils import get_redirect_domain,get_domain,get_request_domain,get_totpurl,encode_qrcode
from .emails import send_email

logger = logging.getLogger(__name__)
django_engine = engines['django']

SUCCEED_RESPONSE = HttpResponse(content='Succeed',status=200)
FORBIDDEN_RESPONSE = HttpResponseForbidden()

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

def _init_userflow_pagelayout(request,userflow,container_class):
    if hasattr(userflow,container_class):
        #already initialized
        return

    #initialize the user userflow
    if not userflow.page_layout:
        #userflow has no customized page_layout, use the defaultuserflow's page_layout
        #initialize defaultuserflow,
        _init_userflow(request,userflow.defaultuserflow,container_class)
        #set userflow's page layout to default userflow's page layout
        setattr(userflow,container_class,getattr(userflow.defaultuserflow,container_class))
        userflow.inited_extracss = userflow.defaultuserflow.inited_extracss
    else:
        context={"container_class":container_class}
        page_layout = userflow.page_layout
    
        page_layout = django_engine.from_string(page_layout).render(
            context=context,
            request=request
        )
        setattr(userflow,container_class,page_layout)
    
        if not hasattr(userflow,"inited_extracss"):
            #init extracss
            extracss = userflow.extracss or ""
            userflow.inited_extracss = django_engine.from_string(extracss).render(
                context=context,
                request=request
            )


def _init_userflow_verifyemail(request,userflow):
        if hasattr(userflow,"verifyemail_body_template"):
            return

        #init verify email
        if userflow.verifyemail_body:
            userflow.verifyemail_body_template = django_engine.from_string(userflow.verifyemail_body)
        else:
            _init_userflow(request,userflow.defaultuserflow)
            userflow.verifyemail_body_template = userflow.defaultuserflow.verifyemail_body_template
    
        if not userflow.verifyemail_from:
            _init_userflow(request,userflow.defaultuserflow)
            userflow.verifyemail_from = userflow.defaultuserflow.verifyemail_from

        if not userflow.verifyemail_subject:
            _init_userflow(request,userflow.defaultuserflow)
            userflow.verifyemail_subject = userflow.defaultuserflow.verifyemail_subject



def adb2c_view(request,template,**kwargs):
    domain = request.GET.get('domain', None)
    container_class = request.GET.get('class')
    if not container_class:
        container_class = "{}_container".format(template)
    title = request.GET.get('title', "Signup or Signin")
    userflow = CustomizableUserflow.get_userflow(domain)

    _init_userflow_pagelayout(request,userflow,container_class)

    page_layout = getattr(userflow,container_class)
    extracss = userflow.inited_extracss

    return TemplateResponse(request,"authome/{}.html".format(template),context={"body":page_layout,"extracss":extracss,"title":title})

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
    if request.GET.get(REDIRECT_FIELD_NAME):
        logger.debug("Found next url '{}'".format(request.GET.get(REDIRECT_FIELD_NAME)))
        pass
    else:
        request.session[REDIRECT_FIELD_NAME] = "https://{}/sso/profile".format(get_request_domain(request))
        logger.debug("No next url provided,set the next url to '{}'".format(request.session[REDIRECT_FIELD_NAME]))

    domain = get_redirect_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).profile_edit
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)


def _do_login(*args,**kwargs):
    pass

@never_cache
@csrf_exempt
@psa("/sso/profile/edit/complete")
def profile_edit_complete(request,backend,*args,**kwargs):
    domain = get_redirect_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).profile_edit
    request.http_error_code = 417
    request.http_error_message = "Failed to edit user profile.{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)


@never_cache
@psa("/sso/email/signup/complete")
def email_signup(request,backend):
    domain = get_redirect_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).email_signup
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)

@never_cache
@csrf_exempt
@psa("/sso/email/signup/complete")
def email_signup_complete(request,backend,*args,**kwargs):
    domain = get_redirect_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).email_signup
    request.http_error_code = 417
    request.http_error_message = "Failed to signup a local account..{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)

@never_cache
@psa("/sso/password/reset/complete")
def password_reset(request,backend):
    domain = get_redirect_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).password_reset
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)

@never_cache
@csrf_exempt
@psa("/sso/password/reset/complete")
def password_reset_complete(request,backend,*args,**kwargs):
    domain = get_redirect_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).password_reset
    request.http_error_code = 417
    request.http_error_message = "Failed to reset password..{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)

@never_cache
@psa("/sso/mfa/set/complete")
def mfa_set(request,backend):
    domain = get_redirect_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).mfa_set
    return do_auth(request.backend, redirect_name=REDIRECT_FIELD_NAME)

@never_cache
@csrf_exempt
@psa("/sso/mfa/set/complete")
def mfa_set_complete(request,backend,*args,**kwargs):
    domain = get_redirect_domain(request)
    request.policy = CustomizableUserflow.get_userflow(domain).mfa_set
    request.http_error_code = 417
    request.http_error_message = "Failed to reset password..{}"

    return do_complete(request.backend, _do_login, user=request.user,
                       redirect_name=REDIRECT_FIELD_NAME, request=request,
                       *args, **kwargs)


def _auth_bearer(request):
    bearer_auth = request.META.get('HTTP_AUTHORIZATION').strip() if 'HTTP_AUTHORIZATION' in request.META else ''
    m = bearer_token_re.search(bearer_auth)
    token = None
    if m:
        token = m.group('token')
    if token != settings.SECRET_KEY:
        return False
    return True


bearer_token_re = re.compile("^Bearer\s+(?P<token>\S+)\s*$")
@never_cache
@csrf_exempt
def verify_code_via_email(request):
    if not _auth_bearer(request):
        return FORBIDDEN_RESPONSE

    domain = request.GET.get('domain', None)
    userflow = CustomizableUserflow.get_userflow(domain)
    _init_userflow_verifyemail(request,userflow)

    data = json.loads(request.body.decode())

    verifyemail_body = userflow.verifyemail_body_template.render(
        context=data,
        request=request
    )
    data["email"] = "rocky.chen75@gmail.com"
    send_email(userflow.verifyemail_from,data["email"],userflow.verifyemail_subject,verifyemail_body)
    logger.debug("Successfully send verification email to '{}',domain is '{}'".format(data["email"],domain))
    return SUCCEED_RESPONSE

totp_secret_key_chars = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)'
@never_cache
@csrf_exempt
def totp_generate(request):
    if not _auth_bearer(request):
        return FORBIDDEN_RESPONSE

    userEmail = request.POST.get("email")
    if not userEmail:
        return HttpResponse(content="Email is missint",status=400)
    idp = request.POST.get("idp")
    if not idp:
        return HttpResponse(content="Idp is missint",status=400)

    secret = get_random_string(settings.TOTP_SECRET_KEY_LENGTH,totp_secret_key_chars)

    totpurl = get_totpurl(secret,email,settings.TOTP_ISSUER,settings.TOTP_TIMESTEP,settings.TOTP_PREFIX)

    qrcode = encode_qrcode(totpurl)

    data = {
        "qrCode" : qrcode
    }
    
    return JsonResponse(data,status=200)




