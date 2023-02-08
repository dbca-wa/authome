import jwt
import time
import traceback
import logging
import re
from datetime import timedelta

from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotAllowed,HttpResponseRedirect
from django.template.response import TemplateResponse
from django.apps import apps
from django.utils import timezone
from django.conf import settings
from django.contrib import messages

from .. import models
from .. import utils 

logger = logging.getLogger(__name__)

app_label = models.UserGroup._meta.app_label
app_name = apps.get_app_config(app_label).verbose_name

apple_teamid = utils.env("APPLE_TEAMID")
apple_clientid = utils.env("APPLE_CLIENTID")
apple_audience = utils.env("APPLE_AUDIENCE",default="https://appleid.apple.com")
apple_secretkey_expiredays = utils.env("APPLE_SECRETKEY_EXPIREDAYS",default=180)
apple_p8file_extension = utils.env("APPLE_P8FILE_EXTENSION",default=".p8")

apple_p8file_re = re.compile("^-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----$",flags=re.DOTALL)

def renew_apple_secretkey(request):
    try:
        if request.method == "GET":
            context={"app_label":app_label,"app_name":app_name,"teamid":apple_teamid,"clientid":apple_clientid,"expiredays":apple_secretkey_expiredays,"p8file_extension":apple_p8file_extension}
            return TemplateResponse(request,"authome/renew_apple_secretkey.html",context=context)
        elif request.method == "POST":
            teamid = request.POST.get("teamid","").strip() or apple_teamid
            clientid = request.POST.get("clientid","").strip() or apple_clientid
            keyid = request.POST.get("keyid","").strip()
            expiredays = int(request.POST.get("expiredays").strip() or apple_secretkey_expredays)
    
            context={"app_label":app_label,"app_name":app_name,"teamid":teamid,"clientid":clientid,"expiredays":expiredays,"keyid":keyid,"p8file_extension":apple_p8file_extension}

            if "p8file" not in request.FILES or not request.FILES["p8file"]:
                messages.error(request, 'Please update the p8 file downloaded from apple website')
                return TemplateResponse(request,"authome/renew_apple_secretkey.html",context=context)
            if request.FILES["p8file"].size >= 10240:
                messages.error(request, 'Please update the correct p8 file downloaded from apple website')
                return TemplateResponse(request,"authome/renew_apple_secretkey.html",context=context)
    
            if not keyid:
                messages.error(request, 'Please input the key id which is returned by Apple along with .p8 file')
                return TemplateResponse(request,"authome/renew_apple_secretkey.html",context=context)

    
            private_key = request.FILES["p8file"].read()
            if isinstance(private_key,bytes):
                private_key = private_key.decode()
            if not apple_p8file_re.match(private_key):
                messages.error(request, '.p8 file is corrupted.')
                return TemplateResponse(request,"authome/renew_apple_secretkey.html",context=context)
            
            now = timezone.localtime()
            expireat = now + timedelta(days=180)
            timestamp_now = int(time.mktime(now.timetuple()))
            timestamp_exp = int(time.mktime(expireat.timetuple()))
            data = {
                    "iss": teamid,
                    "iat": timestamp_now,
                    "exp": timestamp_exp,
                    "aud": apple_audience,
                    "sub": clientid
                }
            token = jwt.encode(payload=data, key=private_key, algorithm="ES256", headers={"kid": keyid})
            context["secretkey"] = token
            context["secretkey_expireat"] = utils.format_datetime(expireat)
            return TemplateResponse(request,"authome/apple_secretkey.html",context=context)
        else:
            return HttpResponseNotAllowed(["GET","POST"])
    except Exception as ex:
        messages.error(request, 'Failed to get apple secret key.{}'.format(str(ex)))
        logger.error('Failed to get apple secret key.{}'.format(traceback.format_exc()))
        return HttpResponseRedirect(request.path)
 
    
