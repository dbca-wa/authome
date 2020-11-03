from django.http import HttpResponseRedirect, HttpResponse, HttpResponseForbidden,JsonResponse 
from django.template.response import TemplateResponse
from django.contrib.auth import login, logout
from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
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
from authome.cache import get_cache

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

def _populate_response(request,f_cache,cache_key,user,current_ip):
    response_contents = {
        'email': user.email,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'client_logon_ip': current_ip
    }
    if request.session.session_key:
        response_contents['session_key'] = request.session.session_key


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
    f_cache(cache_key,[response.content, cache_headers])
    logger.debug("cache the sso auth data for the user({}) with key({})".format(user.email,cache_key))

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

    logger.debug("The user({}) is authenticated".format(request.user.email))
    cache = get_cache()
    user = request.user
    current_ip,routable = get_client_ip(request)
    auth_key = cache.get_auth_key(user.email,request.session.session_key)
    auth_content = cache.get_auth(auth_key)

    if auth_content:
        logger.debug("The user({}) is authenticated and cached".format(request.user.email))

        if auth_content[1]['X-client-logon-ip'] != current_ip:
            auth_content[0] = json.loads(auth_content[0].decode())

            auth_content[0]['client_logon_ip'] = current_ip
            auth_content[1]['X-client-logon-ip'] = current_ip
                    
            auth_content[0] = json.dumps(auth_content[0]).encode()

            cache.update_auth(auth_key, auth_content, 3600)

        response = check_authorization(request,request.user.email)
        if response:
            return response
        else:
            return _populate_response_from_cache(auth_content)
    else:
        response = _populate_response(request,cache.set_auth,auth_key,user,current_ip)

        res = check_authorization(request,request.user.email)
        if res:
            return res

        return response

AUTH_REQUIRED_RESPONSE = HttpResponse(status=401)
AUTH_REQUIRED_RESPONSE.content = "Authentication required"

@csrf_exempt
def auth(request):
    res = _auth(request)
    if not res:
        return AUTH_REQUIRED_RESPONSE
    else:
        return res

BASIC_AUTH_REQUIRED_RESPONSE = HttpResponse(status=401)
BASIC_AUTH_REQUIRED_RESPONSE["WWW-Authenticate"] = 'Basic realm="Please login with your email address"'
BASIC_AUTH_REQUIRED_RESPONSE.content = "Basic auth required"

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
            return BASIC_AUTH_REQUIRED_RESPONSE

    cache = get_cache()

    username, token = parse_basic(token_auth)
    # grab IP address from the request
    current_ip,routable = get_client_ip(request)

    token_auth_key = cache.get_token_auth_key(username,token) 
    token_auth_content = cache.get_token_auth(token_auth_key)
    if token_auth_content[2] != token:
        # token does not match
        cache.delete_token_auth(token_auth_key)
        token_auth_content = None

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

            cache.update_token_auth(token_auth_key, token_auth_content, 3600)
            
        response = check_authorization(request,useremail)
        if response:
            #not authorized
            return response
        else:
            return _populate_response_from_cache(token_auth_content)
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

                response = _populate_response(request,cache.set_token_auth,token_auth_key,user,current_ip)
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

@csrf_exempt
def access_token(request):
    user = request.user
    if not user.is_authenticated:
        return AUTH_REQUIRED_RESPONSE
    else:
        data = {
            'email': user.email,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
        }
        try:
            if not user.token or not user.token.enabled:
                data["error"] = "Access token is not enabled, please ask administrator to enable."
            elif not user.token.token:
                data["error"] = "Access token is created, please ask administrator to create"
            elif user.token.is_expired:
                data["error"] = "Access token is expired, please ask administroator to recreate"
                data["access_token"] = user.token.token
                data["created"] = timezone.localtime(user.token.created).strftime("%Y-%m-%d %H:%M:%S")
                data["expired"] = user.token.expired.strftime("%Y-%m-%d")
            else:
                data["access_token"] = user.token.token
                data["created"] = timezone.localtime(user.token.created).strftime("%Y-%m-%d %H:%M:%S")
                if user.token.expired:
                    data["expired"] = user.token.expired.strftime("%Y-%m-%d")
        except Exception as ex:
            logger.error("Failed to get access token for the user({}).{}".format(user.email,traceback.format_exc()))
            data["error"] = str(ex)

    return JsonResponse(data)

