import re

from django.utils import timezone
from django.contrib.auth import login

from .views import SUCCEED_RESPONSE
from .. import models

def login_user(request):
    email = request.GET.get("user")
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

    request.session["idp"] = idp.idp
    login(request,user,'django.contrib.auth.backends.ModelBackend')

    request.session["idp"] = idp.idp
    request.session["session_timeout"] = 3600

    return SUCCEED_RESPONSE

