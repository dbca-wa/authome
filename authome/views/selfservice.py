from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.conf import settings
from django.utils import timezone
from django.contrib import messages
from django.core.exceptions import ObjectDoesNotExist

import re
import logging
import urllib.parse
from ipware.ip import get_client_ip

from .. import models
from ..cache import cache
from .. import utils
from .views  import get_absolute_url, _populate_response,_get_userflow_pagelayout,_get_next_url,MFA_METHOD_MAPPING

logger = logging.getLogger(__name__)

def user_setting(request):
    #get the auth response
    user = request.user
    auth_key = request.session.session_key
    back_url = request.GET.get("back") or request.POST.get("back")
    logout_url = request.GET.get("logout") or request.POST.get("logout")
    domain = utils.get_host(request)
    next_url = "https://{}/sso/setting".format(domain)
    parameters = None
    if not back_url:
        if domain != settings.AUTH2_DOMAIN:
            back_url = "https://{}".format(domain)
    else:
        back_url = get_absolute_url(back_url,domain)
        parameters = "back={}".format(urllib.parse.quote(back_url))

    if not logout_url:
        logout_url = "https://{}/sso/auth_logout".format(domain)
    else:
        logout_url = get_absolute_url(logout_url,domain)
        if parameters: 
            parameters = "{}&logout={}".format(parameters,urllib.parse.quote(logout_url))
        else:
            parameters = "logout={}".format(urllib.parse.quote(logout_url))

    if parameters:
        next_url = "https://{}/sso/setting?{}".format(domain,parameters)
    else:
        next_url = "https://{}/sso/setting".format(domain)
    next_url = urllib.parse.quote(next_url)

    response = None if (request.session.cookie_changed or request.session.is_empty()) else cache.get_auth(user,auth_key,user.modified)
    if not response:
        response = _populate_response(request,cache.set_auth,auth_key,user,request.session.cookie_value)

    #populte the profile from response headers
    context = {}
    msg = request.GET.get("message") 
    if msg:
        context["message"] = msg
    for key,value in response.items():
        if key.startswith("X-"):
            key = key[2:].replace("-","_")
            context[key] = value

    context["back_url"] = back_url
    context["logout_url"] = logout_url
    context["next_url"] = next_url

    current_ip,routable = get_client_ip(request)
    context['client_logon_ip'] = current_ip
    context["mfa_enabled"] = False
    context["password_reset_enabled"] = False
    context["mfa_method"] = ""
    if settings.AUTH2_CLUSTER_ENABLED:
        context["auth2_cluster"] = settings.AUTH2_CLUSTERID

    if request.session.get("mfa_method"):
        context["mfa_method"] = MFA_METHOD_MAPPING.get(request.session["mfa_method"],request.session["mfa_method"])
    if request.session.get("idp"):
        idp = models.IdentityProvider.objects.filter(idp=request.session["idp"]).first()
        if idp:
            context["idp"] = idp.name
            if idp.idp == "local":
                context["mfa_enabled"] = True
            if idp.idp.startswith("local"):
                context["password_reset_enabled"] = True


    context["is_active"] = request.user.is_active
    context["is_staff"] = request.user.is_staff
    context["is_superuser"] = request.user.is_superuser
    context["logout_enabled"] = request.user.is_staff and request.get_host() == settings.AUTH2_DOMAIN

 
    domain = utils.get_host(request)
    page_layout,extracss = _get_userflow_pagelayout(request,domain)

    groups = models.UserGroup.find_groups(context["email"])[0]
    context["groups"] = " , ".join(g.name for g in groups)
    session_timeout = models.UserGroup.get_session_timeout(groups)
    context["session_timeout"] = utils.format_timedelta(session_timeout)
    if not session_timeout:
        expireat  = request.session.expireat
        if expireat:
            context["session_expireat"]  =  utils.format_datetime(expireat)
        else:
            context["session_age"]  =  utils.format_timedelta(request.session.get_session_cookie_age(),unit='s')


    context["body"] = page_layout
    token = models.UserToken.objects.filter(user = user).first()
    if not token:
        token = models.UserToken(user=user)
    context["token"] = token
    context["token_lifetime"] = [(i,settings.USER_ACCESS_TOKEN_LIFETIME_SELFSERVICE[i]) for i in range(len(settings.USER_ACCESS_TOKEN_LIFETIME_SELFSERVICE))]

    return TemplateResponse(request,"authome/setting.html",context=context)

def _get_redirect_url(request,msg=None):
    next_url = request.GET.get("next") if request.method == 'GET' else request.POST.get("next") 
    if not next_url:
        next_url = _get_next_url(request)

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
    if msg:
        if "?" in next_url:
            next_url = "{}&message={}".format(next_url,msg)
        else:
            next_url = "{}?message={}".format(next_url,msg)

    return next_url

def profile_edit(request):
    """
    View method for path '/sso/selfservice/profile/edit'
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
        action = request.POST.get("action")
        msg = None
        if action == "change":
            first_name = (request.POST.get("first_name") or "").strip()
            last_name = (request.POST.get("last_name") or "").strip()
            if not first_name:
                context = _get_context(_get_redirect_url(request))
                context["messages"] = [("error","Fist name is empty")]
                return TemplateResponse(request,"authome/profile_edit.html",context=context)
            if not last_name:
                context = _get_context(_get_redirect_url(request))
                context["messages"] = [("error","Last name is empty")]
                return TemplateResponse(request,"authome/profile_edit.html",context=context)
    
            if request.user.first_name != first_name or request.user.last_name != last_name:
                request.user.first_name = first_name
                request.user.last_name = last_name
                request.user.save(update_fields=["first_name","last_name","modified"])
                if settings.AUTH2_CLUSTER_ENABLED:
                    changed_clusters,not_changed_clusters,failed_clusters = cache.user_changed(request.user.id)
                    if failed_clusters:
                        msg = "Failed to send change event of the user({1}<{0}>) to some cluseters.{2} ".format(request.user.id,request.user.email,["{}:{}".format(c,str(e)) for c,e in failed_clusters])

        return HttpResponseRedirect(_get_redirect_url(request,msg))


def _enable_token(request,enable):
    user = request.user
    msg = None
    if not user.is_authenticated:
        #not authenticated
        return HttpResponseRedirect(_get_redirect_url(request,"User is not authenticated"))

    try:
        try:
            token = models.UserToken.objects.get(user=user)
            if enable:
                if not token.enabled:
                    token.enabled = True
                    token.save(update_fields=["enabled"])
            else:
                if token.enabled:
                    token.enabled = False
                    token.save(update_fields=["enabled"])
        except ObjectDoesNotExist as ex:
            if enable:
                models.UserToken(user=user,enabled=True).save()
        msgs = messages.get_messages(request)
        if msgs:
            msg = "\n".join(str(m) for m  in msgs if m.level in (messages.WARNING,messages.ERROR))
    except Exception as ex:
        msg = "{}:Failed to {} the access token..{}".format(user.email,"enable" if enable else "disable",traceback.format_exc())
        logger.error(msg)

    return HttpResponseRedirect(_get_redirect_url(request,msg))

def enable_token(request):
    return _enable_token(request,True)

def disable_token(request):
    return _enable_token(request,False)

def revoke_token(request):
    msg = None
    user = request.user
    if not user.is_authenticated:
        #not authenticated
        return HttpResponseRedirect(_get_redirect_url(request,"User is not authenticated"))

    try:
        try:
            token = models.UserToken.objects.get(user=user)
            if token.token:
                token.token = None
                token.created = None
                token.expired = None
                token.save(update_fields=["token","created","expired"])
        except ObjectDoesNotExist as ex:
            pass
        msgs = messages.get_messages(request)
        if msgs:
            msg = "\n".join(str(m) for m  in msgs if m.level in (messages.WARNING,messages.ERROR))
    except Exception as ex:
        msg = "{}:Failed to revoke access token..{}".format(user.email,traceback.format_exc())
        logger.error(msg)

    return HttpResponseRedirect(_get_redirect_url(request,msg))

def create_token(request,index):
    user = request.user
    msg = None
    if not user.is_authenticated:
        #not authenticated
        return HttpResponseRedirect(_get_redirect_url(request,"User is not authenticated"))

    try:
        enable_token = 0
        #enable the access token if not enabled before
        try:
            token = models.UserToken.objects.get(user=user)
            if not token.enabled:
                token.enabled = True
                enable_token = 1
        except ObjectDoesNotExist as ex:
            token = models.UserToken(user=user,enabled=True)
            enable_token = 2

        token.generate_token(token_lifetime=settings.USER_ACCESS_TOKEN_LIFETIME_SELFSERVICE[index])
        if enable_token == 2:
            token.save()
        elif enable_token == 1:
            token.save(update_fields=["enabled","token","created","expired"])
        else:
            token.save(update_fields=["token","created","expired"])

        msgs = messages.get_messages(request)
        if msgs:
            msg = "\n".join(str(m) for m  in msgs if m.level in (messages.WARNING,messages.ERROR))
    except Exception as ex:
        msg = "{}:Failed to generate access token..{}".format(user.email,traceback.format_exc())
        logger.error(msg)

    return HttpResponseRedirect(_get_redirect_url(request,msg))

