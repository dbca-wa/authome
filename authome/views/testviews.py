import re
from collections import OrderedDict

from django.utils import timezone
from django.contrib.auth import login
from django.http import HttpResponse, JsonResponse

from . import views
from .. import models
from .. import utils

def login_user(request):
    email = request.GET.get("user")
    if not email:
        return HttpResponse(status=400,content="Parameter 'user' is missing.")
    enabletoken = (request.GET.get("enabletoken") or "true").lower() == "true"
    refreshtoken = (request.GET.get("refreshtoken") or "false").lower() == "true"

    user = models.User.objects.filter(email=email).first()
    if not user:
        name = email.split("@",1)[0]
        nameparts = None
        firstname = name
        lastname = "test"
        for sep in [".","_","-"]:
            nameparts = name.split("_",1)
            if len(nameparts) == 1:
                continue
            elif sep == ".":
                firstname,lastname = nameparts
                break
            else :
                lastname,firstname = nameparts
                break

        dbcagroup = models.UserGroup.dbca_group()
        usergroups = models.UserGroup.find_groups(email)[0]
        if any(group.is_group(dbcagroup) for group in usergroups ):
            is_staff = True
        else:
            is_staff = False
    else:
        firstname = user.first_name
        lastname = user.last_name
        is_staff = user.is_staff

    idp,created = models.IdentityProvider.objects.get_or_create(idp=models.IdentityProvider.AUTH_EMAIL_VERIFY[0],defaults={"name":models.IdentityProvider.AUTH_EMAIL_VERIFY[1]})
    user,created = models.User.objects.update_or_create(email=email,username=email,defaults={"is_staff":is_staff,"last_idp":idp,"last_login":timezone.localtime(),"first_name":firstname,"last_name":lastname})

    #enable user token
    token = models.UserToken.objects.filter(user=user).first()
    if enabletoken:
        changed = False
        if not token:
            token = models.UserToken(user=user)
            token.enabled = True
            token.generate_token()
            changed = True
        else:
            if not token.enabled:
                token.enabled = True
                changed = True
            if not token.token or token.is_expired or refreshtoken:
                token.generate_token()
                chaged = True
        if changed:
            token.save()
    else:
        if token and token.enabled:
            token.enabled = False
            token.save(update_fields=["enabled"])

    request.session["idp"] = idp.idp
    login(request,user,'django.contrib.auth.backends.ModelBackend')

    request.session["idp"] = idp.idp
    request.session["session_timeout"] = 3600

    return views.profile(request)

def echo(request):
    data = OrderedDict()
    data["url"] = "https://{}{}".format(utils.get_host(request),request.get_full_path())
    data["method"] = request.method
    
    keys = [k for k in request.GET.keys()]
    keys.sort()
    if keys:
        data["parameters"] = OrderedDict()
    for k in keys:
        v = request.GET.getlist(k)
        if not v:
            data["parameters"][k] = v
        elif len(v) == 1:
            data["parameters"][k] = v[0]
        else:
            data["parameters"][k] = v

    keys = [k for k in request.COOKIES.keys()]
    keys.sort()
    if keys:
        data["cookies"] = OrderedDict()
    for k in keys:
        v = request.COOKIES[k]
        data["cookies"][k] = v


    keys = [k for k in request.headers.keys()]
    keys.sort()
    if keys:
        data["headers"] = OrderedDict()
    for k in keys:
        v = request.headers[k]
        data["headers"][k.lower()] = v

    if request.method == "POST":
        data["body"] = OrderedDict()
        keys = [k for k in request.POST.keys()]
        keys.sort()
        for k in keys:
            v = request.POST.getlist(k)
            if not v:
                data["body"][k] = v
            elif len(v) == 1:
                data["body"][k] = v[0]
            else:
                data["body"][k] = v

    return JsonResponse(data,status=200)
