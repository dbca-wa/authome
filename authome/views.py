from django.http import HttpResponseRedirect, HttpResponse, HttpResponseForbidden
from django.contrib.auth import login, logout, get_user_model
from django.urls import reverse
from django.core.cache import cache
from django.shortcuts import render
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.http import urlencode
from ipware.ip import get_ip
import json
import base64
import hashlib
import adal
import re

from django.contrib.auth.models import User
from authome.models import UserSession

def force_email(username):
    if username.find("@") == -1:
        candidate = User.objects.filter(
            username__iexact=username).first()
        return candidate.email if candidate else None
    return username


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


def adal_authenticate(email, password):
    try:
        context = adal.AuthenticationContext(settings.AZUREAD_AUTHORITY)
        token = context.acquire_token_with_username_password(
            settings.AZUREAD_RESOURCE, email, password,
            settings.SOCIAL_AUTH_AZUREAD_OAUTH2_KEY,
            settings.SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET
        )

    except adal.adal_error.AdalError:
        return None

    candidates = User.objects.filter(email__iexact=token['userId']).first()
    return candidates


def shared_id_authenticate(email, shared_id):
    us = UserSession.objects.filter(user__email__iexact=email).order_by('-session__expire_date').first()
    if (not us) or (us.shared_id != shared_id):
        return None
    return us.user


@csrf_exempt
def auth_get(request):
    # If user is using SSO, do a normal auth check.
    if request.user.is_authenticated:
        return auth(request)

    if 'sso_user' in request.GET and 'sso_shared_id' in request.GET:
        user = shared_id_authenticate(request.GET.get('sso_user'), 
            request.GET.get('sso_shared_id'))
        if user:
            response_data = json.dumps({
                'email': user.email, 
                'shared_id': request.GET.get('sso_shared_id')
            })
            response = HttpResponse(response_data, content_type='application/json')
            response["X-email"] = user.email
            response["X-shared-id"] = request.GET.get('sso_shared_id')
            return response

    return HttpResponseForbidden()


@csrf_exempt
def auth_dual(request):
    # If user has a SSO cookie, do a normal auth check.
    if request.user.is_authenticated:
        return auth(request)

    # else return an empty response
    response = HttpResponse('{}', content_type='application/json')
    return response

    
@csrf_exempt
def auth_ip(request):
    # Get the IP of the current user, try and match it up to a session.
    current_ip = get_ip(request)

    # If there's a basic auth header, perform a check.
    basic_auth = request.META.get('HTTP_AUTHORIZATION').strip() if 'HTTP_AUTHORIZATION' in request.META else ''
    if basic_auth:
        # Check basic auth against Azure AD as an alternative to SSO.
        username, password = parse_basic(basic_auth)
        username = force_email(username)
        user = shared_id_authenticate(username, password)
        
        if not user:
            user = adal_authenticate(username, password)

        if user:
            response_data = json.dumps({
                'email': user.email, 
                'client_logon_ip': current_ip
            })
            response = HttpResponse(response_data, content_type='application/json')
            response["X-email"] = user.email
            response["X-client-logon-ip"] = current_ip
            return response

    # If user has a SSO cookie, do a normal auth check.
    if request.user.is_authenticated:
        return auth(request)

    headers = {'client_logon_ip': current_ip}

    # We can assume that the Session and UserSession tables only contain
    # current sessions.
    usersession = UserSession.objects.filter(
                      session__isnull=False,
                      ip=current_ip).order_by("-session__expire_date").first()

    if usersession:
        headers["email"] = usersession.user.email

    response = HttpResponse(json.dumps(headers), content_type='application/json')
    for key, val in headers.items():
        key = "X-" + key.replace("_", "-")
        response[key] = val

    return response


@csrf_exempt
def auth(request):
    # grab the basic auth data from the request
    basic_auth = request.META.get('HTTP_AUTHORIZATION').strip() if 'HTTP_AUTHORIZATION' in request.META else ''
    basic_hash = hashlib.sha1(basic_auth.encode('utf-8')).hexdigest() if basic_auth else None
    # grab IP address from the request
    current_ip = get_ip(request)


    # store the access IP in the current user session 
    if request.user.is_authenticated:
        usersession = UserSession.objects.filter(
            session_id=request.session.session_key).order_by("-session__expire_date").first()
        if not usersession:
            usersession, created = UserSession.objects.get_or_create(user=request.user,
                                                    session_id=request.session.session_key,
                                                    ip=current_ip)
            usersession.save()

        if usersession.ip != current_ip:
            usersession.ip = current_ip
            usersession.save()

    # check the cache for a match for the basic auth hash
    if basic_hash:
        cachekey = "auth_cache_{}".format(basic_hash)
        content = cache.get(cachekey)
        if content:
            response = HttpResponse(content[0], content_type='application/json')
            for key, val in content[1].items():
                response[key] = val
            response["X-auth-cache-hit"] = "success"

            # for a new session using cached basic auth, reauthenticate
            if not request.user.is_authenticated:
                user = User.objects.get(email__iexact=content[1]['X-email'])
                user.backend = "django.contrib.auth.backends.ModelBackend"
                login(request, user)
            return response

    # check the cache for a match for the current session key
    cachekey = "auth_cache_{}".format(request.session.session_key)
    content = cache.get(cachekey)
    # return a cached response ONLY if the current session has an authenticated user
    if content and request.user.is_authenticated:
        response = HttpResponse(content[0], content_type='application/json')
        for key, val in content[1].items():
            response[key] = val
        response["X-auth-cache-hit"] = "success"
        return response

    cache_basic = False
    user = None
    if not request.user.is_authenticated:
        # Check basic auth against Azure AD as an alternative to SSO.
        try:
            username, password = parse_basic(basic_auth)
            username = force_email(username)

            # first check for a shared_id match
            # if yes, provide a response, but no session cookie
            # (hence it'll only work against certain endpoints)
            user = shared_id_authenticate(username, password)
            if user:
                response_data = json.dumps({
                    'email': user.email, 
                    'shared_id': password
                })
                response = HttpResponse(response_data, content_type='application/json')
                response["X-email"] = user.email
                response["X-shared-id"] = password
                return response

            # after that, check against Azure AD
            user = adal_authenticate(username, password)
            # basic auth using username/password will generate a session cookie
            if user:
                user.backend = "django.contrib.auth.backends.ModelBackend"
                login(request, user)
                cache_basic = True
            else:
                raise Exception('Authentication failed')
        except Exception as e:
            response = HttpResponse(status=401)
            response[
                "WWW-Authenticate"] = 'Basic realm="Please login with your email address"'
            response.content = str(e)
            return response
    else:
        user = request.user

    us = UserSession.objects.filter(user__email=user.email).order_by('-session__expire_date').first()
    response_contents = {
        'email': user.email,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'shared_id': us.shared_id,
        'session_key': request.session.session_key,
        'client_logon_ip': current_ip
    }
    response = HttpResponse(json.dumps(response_contents), content_type='application/json')
    headers = response_contents
    headers["full_name"] = u"{}, {}".format(
        headers.get("last_name", ""), 
        headers.get("first_name", "")
    )
    headers["logout_url"] = "/sso/auth_logout"
   
    # cache response
    cache_headers = dict()
    for key, val in headers.items():
        key = "X-" + key.replace("_", "-")
        cache_headers[key], response[key] = val, val
    # cache authentication entries
    if basic_hash and cache_basic:
        cache.set("auth_cache_{}".format(basic_hash), (response.content, cache_headers), 3600)
    cache.set("auth_cache_{}".format(request.session.session_key), (response.content, cache_headers), 3600)

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