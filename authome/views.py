from django.http import HttpResponseRedirect, HttpResponse, HttpResponseForbidden
from django.template.response import TemplateResponse
from django.contrib.auth import login, logout
from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
from django.core.cache import cache
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.http import urlencode
from django.utils import timezone
from ipware.ip import get_client_ip
import json
import base64
import hashlib
import msal
import re
import traceback
import logging
from datetime import datetime

from django.contrib.auth.models import User
from authome.models import can_access,UserToken

logger = logging.getLogger(__name__)

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

NON_AUTHORIZED_RESPONSE = HttpResponseForbidden()
def check_authorization(request,useremail):
   """
   Return None if authorized;otherwise return Authorized failed response
   """
   domain = request.headers["x-upstream-server-name"] or request.get_host()
   path = request.headers["x-upstream-request-uri"] or request.path
   try:
       path = path[:path.index("?")]
   except:
       pass

   if can_access(useremail,domain,path):
       return None
   else:
       return NON_AUTHORIZED_RESPONSE


def basic_authenticate(email, password):
    try:
        app = msal.PublicClientApplication(settings.SOCIAL_AUTH_AZUREAD_OAUTH2_KEY,authority="https://login.microsoftonline.com/organizations")
        result = None
    
        # Firstly, check the cache to see if this end user has signed in before
        accounts = app.get_accounts(username=email)
        if accounts:
            result = app.acquire_token_silent(config["scope"], account=accounts[0])
    
        if not result:
            # See this page for constraints of Username Password Flow.
            # https://github.com/AzureAD/microsoft-authentication-library-for-python/wiki/Username-Password-Authentication
            result = app.acquire_token_by_username_password(email, password, scopes=["User.ReadBasic.All"])

        if "error" in result:
            raise Exception(str(result))
    
        if "access_token" in result:
            # Calling graph using the access token
            toekn = result["access_token"]
    except :
        traceback.print_exc()
        return None

    candidates = User.objects.filter(email__iexact=token['userId']).first()
    return candidates

def _populate_response(request,cache_key,user,current_ip):
    response_contents = {
        'email': user.email,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'session_key': request.session.session_key,
        'client_logon_ip': current_ip
    }

    response = HttpResponse(json.dumps(response_contents), content_type='application/json')
    headers = response_contents
    headers["full_name"] = u"{}, {}".format(user.last_name,user.first_name)
    headers["logout_url"] = "/sso/auth_logout"

    # cache response
    cache_headers = dict()
    for key, val in headers.items():
        key = "X-" + key.replace("_", "-")
        cache_headers[key], response[key] = val, val
    # cache authentication entries
    cache.set(cache_key,[response.content, cache_headers],3600)
    logger.debug("{}:cache the sso auth data with key({})".format(user.email,cache_key))

    return response

def _populate_response_from_cache(content):
    response = HttpResponse(content[0], content_type='application/json')
    for key, val in content[1].items():
        response[key] = val
    response["X-auth-cache-hit"] = "success"
    return response


def _auth(request):
    if not request.user.is_authenticated:
        logger.debug("User is not authenticated")
        return None

    logger.debug("{} is authenticated".format(request.user.email))

    user = request.user
    current_ip,routable = get_client_ip(request)
    auth_key = "auth_cache_{}".format(request.session.session_key)
    auth_content = cache.get(auth_key)

    if auth_content:
        logger.debug("{}:sso auth is authenticated and cached".format(request.user.email))

        if auth_content[1]['X-client-logon-ip'] != current_ip:
            auth_content[0] = json.loads(auth_content[0].decode())

            auth_content[0]['client_logon_ip'] = current_ip
            auth_content[1]['X-client-logon-ip'] = current_ip
                    
            auth_content[0] = json.dumps(auth_content[0]).encode()

            cache.set(auth_key, auth_content, 3600)

        response = check_authorization(request,request.user.email)
        if response:
            return response
        else:
            return _populate_response_from_cache(auth_content)
    else:
        response = _populate_response(request,auth_key,user,current_ip)

        res = check_authorization(request,request.user.email)
        if res:
            return res

        return response

AUTH_REQUIRED_RESPONSE = HttpResponse(status=401)
AUTH_REQUIRED_RESPONSE.content = "Basic auth required"

@csrf_exempt
def auth(request):
    res = _auth(request)
    if not res:
        return AUTH_REQUIRED_RESPONSE
    else:
        return res

basic_auth_REQUIRED_RESPONSE = HttpResponse(status=401)
basic_auth_REQUIRED_RESPONSE["WWW-Authenticate"] = 'Basic realm="Please login with your email address"'
basic_auth_REQUIRED_RESPONSE.content = "Basic auth required"

@csrf_exempt
def auth_basic(request):
    """
    First authenticate with basic auth and then fall back to session authentication
    """
    basic_auth = request.META.get('HTTP_AUTHORIZATION').strip() if 'HTTP_AUTHORIZATION' in request.META else ''
    if not basic_auth:
        #not provide basic auth data,check whether session is already authenticated or not.
        res = _auth(request)
        if res:
            #already authenticated
            return res
        else:
            #require the user to provide credential using basic auth
            return basic_auth_REQUIRED_RESPONSE

    basic_hash = hashlib.sha1(basic_auth.encode('utf-8')).hexdigest() 
    # grab IP address from the request
    current_ip,routable = get_client_ip(request)

    basic_auth_key = "basicauth_cache_{}".format(basic_hash) 
    basic_auth_content = cache.get(basic_auth_key)

    if basic_auth_content:
        #already authenticated with basic auth data, using the basic auth data instead of current session authentication data (if have)
        user = User.objects.get(email__iexact=basic_auth_content[1]['X-email'])
        request.user = user
        request.session.modified = False
        useremail = user.email

        if basic_auth_content[1]['X-client-logon-ip'] != current_ip:
            basic_auth_content[0] = json.loads(basic_auth_content[0].decode())

            basic_auth_content[0]['client_logon_ip'] = current_ip
            basic_auth_content[1]['X-client-logon-ip'] = current_ip
                    
            basic_auth_content[0] = json.dumps(basic_auth_content[0]).encode()

            cache.set(basic_auth_key, basic_auth_content, 3600)
            
        response = check_authorization(request,useremail)
        if response:
            #not authorized
            return response
        else:

            return _populate_response_from_cache(auth_content)
    else:
        username = ""
        try:
            username, password = parse_basic(basic_auth)
            if "@" not in username:
                #username is not an email address, replace it with email address
                user = User.objects.filter(username__iexact=username).first()
                if not user:
                    raise Exception("User({}) doesn't exist".format(username))
                username = user.email

            if request.user.is_authenticated and username == request.user.email:
                #the user of the basic auth is the same as the authenticated session user;use the session authentication data directly
                return _auth(request)

            user = basic_authenticate(username, password)
            if user:
                logger.debug("Succeed to authenticate the user({}) with password".format(username))
                request.user = user
                request.session.modified = False

                response = _populate_response(request,basic_auth_key,user,current_ip)
                res = check_authorization(request,user.email)
                if res:
                    return res
                else:
                    return response
            else:
                res = _auth(request)
                if res:
                    #already authenticated
                    logger.debug("Failed to authenticate the user({}) with password, fall back to use session authentication".format(username))
                    return res
                else:
                    #require the user to provide credential using basic auth
                    logger.debug("Failed to authenticate the user({}) with password".format(username))
                    raise Exception('Authentication failed')

        except Exception as e:
            response = HttpResponse(status=401)
            response["WWW-Authenticate"] = 'Basic realm="Please login with your email address and password"'
            response.content = str(e)
            return response

@csrf_exempt
def auth_token(request):
    """
    First authenticate the token and then fall back to session authentication
    """
    token_auth = request.META.get('HTTP_AUTHORIZATION').strip() if 'HTTP_AUTHORIZATION' in request.META else ''
    if not token_auth:
        #not provide basic auth data,check whether session is already authenticated or not.
        res = _auth(request)
        if res:
            #already authenticated
            return res
        else:
            #require the user to provide credential using basic auth
            return token_auth_REQUIRED_RESPONSE

    token_hash = hashlib.sha1(token_auth.encode('utf-8')).hexdigest() 
    # grab IP address from the request
    current_ip,routable = get_client_ip(request)

    token_auth_key = "tokenauth_cache_{}".format(token_hash) 
    token_auth_content = cache.get(token_auth_key)

    if token_auth_content:
        #already authenticated with token auth data, using the token auth data instead of current session authentication data (if have)
        user = User.objects.get(email__iexact=token_auth_content[1]['X-email'])
        request.user = user
        request.session.modified = False
        useremail = user.email

        if token_auth_content[1]['X-client-logon-ip'] != current_ip:
            token_auth_content[0] = json.loads(token_auth_content[0].decode())

            token_auth_content[0]['client_logon_ip'] = current_ip
            token_auth_content[1]['X-client-logon-ip'] = current_ip
                    
            token_auth_content[0] = json.dumps(token_auth_content[0]).encode()

            cache.set(token_auth_key, token_auth_content, 3600)
            
        response = check_authorization(request,useremail)
        if response:
            #not authorized
            return response
        else:

            return _populate_response_from_cache(auth_content)
    else:
        username = ""
        try:
            username, token = parse_basic(token_auth)
            if "@" in username:
                user = User.objects.get(email__iexact=username)
            else:
                user = User.objects.filter(username__iexact=username).first()
                if not user:
                    raise Exception("User({}) doesn't exist".format(username))

            if request.user.is_authenticated and user.email == request.user.email:
                #the user of the token auth is the same as the authenticated session user;use the session authentication data directly
                return _auth(request)

            if user.token and user.token.is_valid(token):
                logger.debug("Succeed to authenticate the user({}) with token".format(username))
                request.user = user
                request.session.modified = False

                response = _populate_response(request,token_auth_key,user,current_ip)
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
                    raise Exception('Authentication failed')

        except Exception as e:
            response = HttpResponse(status=401)
            response["WWW-Authenticate"] = 'Basic realm="Please login with your email address and access token"'
            response.content = str(e)
            return response


def logout_view(request):
    logout(request)
    return HttpResponseRedirect(
        'https://login.windows.net/common/oauth2/logout')


def home(request):
    next_url = request.GET.get('next', None)
    if not request.user.is_authenticated:
        url = reverse('social:begin', args=['azuread-oauth2'])
        if next_url:
            url += '?{}'.format(urlencode({'next': next_url}))
        return HttpResponseRedirect(url)
    if next_url:
        return HttpResponseRedirect('https://{}'.format(next_url))
    return HttpResponseRedirect(reverse('auth'))


def auth_view(request,user_template):
    return TemplateResponse(request, 'authome/{}.html'.format(user_template))
