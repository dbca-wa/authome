import re
import logging
import traceback
import random
import math
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import transaction
from django.db import models as django_models
from django.contrib.postgres.fields.array import ArrayField as DjangoArrayField
from django.db.models.signals import pre_delete, pre_save, post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import AbstractUser,UserManager
from django.utils.html import mark_safe
from django.contrib import messages

import hashlib

from ..cache import cache,get_defaultcache,get_usercache
from .. import signals
from .. import utils
from .debugmodels import DebugLog

logger = logging.getLogger(__name__)

defaultcache = get_defaultcache()

UP_TO_DATE = 1
OUTDATED = -1
OUT_OF_SYNC = -2
CACHE_STATUS_NAME = {
    UP_TO_DATE : "Up to date",
    OUTDATED : "Outdated",
    OUT_OF_SYNC : "Out of sync"
}

help_text_users = """
List all possible user emails in this group separated by new line character.
The following lists all valid options in the checking order
    1. All Emails    : *
    2. Domain Email  : Starts with '@', followed by email domain. For example@dbca.wa.gov.au
    3. Email Pattern : A email pattern,'*' represents any strings. For example test_*@dbca.wa.gov.au
    4. Regex Email   : A regex email, starts with '^' and ends with '$'
    5. User Email    : A single user email, For example test_user01@dbca.wa.gov.au
"""

help_text_domain = """
A domain or domain pattern
The following lists all valid options in the checking order
    1. Single Domain  : Represent a single domain. For example oim.dbca.wa.gov.au.
    2. Domain Pattern : A domain pattern, '*" represents any strings. For example  pbs*dbca.wa.gov.au
    3. Domain Regex   : A regex string starts with '^'. For example  ^pbs[^\\.]*\\.dbca\\.wa\\.gov\\.au$
    4. Suffix Domain  : A string Starts with '.' followed by a domain. For example .dbca.wa.gov.au
    5. All Domain     : '*'
"""

help_text_paths = """
List all possible paths separated by new line character.
The following lists all valid options in the checking order
    1. All path      : *
    2. Prefix path   : the paths except All path, regex path and exact path. For example /admin
    3. Regex path    : A regex string starts with '^'. For example ^.*/add$
    4. Exact path  : Starts with '=', represents a single request path . For example =/register
"""

sortkey_c = django_models.Func('sortkey',function='C',template='(%(expressions)s) COLLATE "%(function)s"')

class ArrayField(DjangoArrayField):
    """
    Customizable ArrayField to provide feature 'clean'
    """
    def clean(self, value, model_instance):
        return super().clean([v for v in value if v],model_instance)

class DbObjectMixin(object):
    """
    A mixin class to provide property "db_obj" which is the object with same id in database
    Return None if the object is a new instance.

    """
    _db_obj = None

    _editable_columns = []

    @property
    def db_obj(self):
        if not self.id:
            return None

        if not self._db_obj:
            self._db_obj = self.__class__.objects.get(id=self.id)
        return self._db_obj

    def save(self,update_fields=None,*args,**kwargs):
        if not self.is_changed(update_fields):
            return

        logger.debug("Try to save the changed {}({})".format(self.__class__.__name__,self))
        with transaction.atomic():
            super().save(update_fields=update_fields,*args,**kwargs)

    def delete(self,*args,**kwargs):
        with transaction.atomic():
            super().delete(*args,**kwargs)

    def is_changed(self,update_fields=None):
        if self.id is None:
            return True

        for name in self._editable_columns:
            if update_fields and name not in update_fields:
                continue
            if getattr(self,name) != getattr(self.db_obj,name):
                return True

        return False


class RequestDomain(object):
    """
    Request domain configuration
    Support four kinds of configuration
    1. All domains.
    2. Suffix domain
    3. Exact domain
    4. Regex domain

    """
    all_domain_re = re.compile("^\\*+$")
    sufix_re = re.compile("^\\**\\.(?P<sufix>([a-zA-Z0-9_\\-]+)(\\.[a-zA-Z0-9_\\-]+)*)$")
    exact_re = re.compile("^([a-zA-Z0-9_\\-]+)(\\.[a-zA-Z0-9_\\-]+)+$")
    #two digit values(10 - 99), high value has low priority
    base_sort_key = 99

    _all_base_sort_keys = None

    @staticmethod
    def all_base_sort_keys():
        if not RequestDomain._all_base_sort_keys:
            RequestDomain._all_base_sort_keys = [c.base_sort_key for c in RequestDomain.__subclasses__()]

        return RequestDomain._all_base_sort_keys

    @staticmethod
    def is_base_sort_key(key):
        return key in RequestDomain.all_base_sort_keys()

    #match all domains if True.
    match_all = False
    def __init__(self,config):
        #the configuration of this request domain
        self.config = config
        #the sort key to sort all configured request domain, the front configuration has high priority than the later configuration
        self.sort_key = self.get_sort_key(config)

    def get_sort_key(self,config):
        return "{:0>2}:{}".format(self.base_sort_key,config)

    @classmethod
    def get_instance(cls,domain):
        """
        Return the appropriate ReqestionDomain instance according the domain configuration
        """
        domain = domain.strip() if domain else None
        if not domain:
            #configured domain is empty
            return None

        #domain should be case insensitive, convert it to lowercase
        domain = domain.lower()
        #if domain is startswith the prefix ("https://"or "http://"), remove the prefix
        for prefix in ("https://","http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
                break

        if cls.all_domain_re.search(domain):
            #all request domain,
            return AllRequestDomain()

        m = cls.sufix_re.search(domain)
        if m:
            #suffex domain
            return SufixRequestDomain(".{}".format(m.group("sufix")))

        elif cls.exact_re.search(domain):
            #exact domain
            return ExactRequestDomain(domain)
        else:
            #regex domain
            return RegexRequestDomain(domain)

    def match(self,domain):
        return False

class AllRequestDomain(RequestDomain):
    """
    Has the lowest priority
    Match all domains
    """
    base_sort_key = 99
    match_all = True

    def __init__(self):
        super().__init__("*")

    def match(self,domain):
        return True

class ExactRequestDomain(RequestDomain):
    """
    Has the highest priority, match the single domain
    """
    base_sort_key = 10

    def match(self,domain):
        return self.config == domain

class SufixRequestDomain(RequestDomain):
    """
    match all domains which are endswith the configure domain
    """
    base_sort_key = 60

    def match(self,domain):
        if not domain:
            return False
        return domain.endswith(self.config)

class RegexRequestDomain(RequestDomain):
    """
    The configure domain uses '*' represents any number of any characters
    Match all domains which is identified by configured domain
    """
    base_sort_key = 40
    def __init__(self,domain):
        super().__init__(domain)
        try:
            if domain.startswith("^") :
                self._re = re.compile(domain)
            else:
                self._re = re.compile("^{}$".format(domain.replace(".","\\.").replace("*","[a-zA-Z0-9\\._\\-]*")))
        except Exception as ex:
            raise ValidationError("The regex domain config({}) is invalid.{}".format(domain,str(ex)))

    def get_sort_key(self,config):
        return "{:0>2}:{}".format(self.base_sort_key,config.replace("*","~"))

    def match(self,domain):
        if not domain:
            return False

        return True if self._re.search(domain) else False

class CacheableMixin(object):

    @classmethod
    def get_model_change_cls(cls):
        return None

    @classmethod
    def is_outdated(cls):
        return cls.get_model_change_cls().is_changed()

    @classmethod
    def cache_status(cls):
        return cls.get_model_change_cls().status()

    @classmethod
    def get_cachetime(cls):
        return cls.get_model_change_cls().get_cachetime()

    @classmethod
    def get_next_refreshtime(cls):
        return cls.get_model_change_cls().get_next_refreshtime()

    @classmethod
    def refresh_cache(cls):
        pass

    @classmethod
    def refresh_cache_if_required(cls):
        cls.get_model_change_cls().refresh_cache_if_required()


class IdentityProvider(CacheableMixin,DbObjectMixin,django_models.Model):
    """
    The identity provider to authenticate user.
    IdentityProvider 'local' means local account
    IdentityProvider 'local_passwordless' means autenticating user without password
    """
    AUTH_EMAIL_VERIFY = ("auth_email_verify","Sign in with Passcode")
    MANUALLY_LOGOUT = 1
    AUTO_LOGOUT = 2
    AUTO_LOGOUT_WITH_POPUP_WINDOW = 3

    LOGOUT_METHODS = (
        (MANUALLY_LOGOUT,"Manually Logout"),
        (AUTO_LOGOUT,"Auto Logout"),
        (AUTO_LOGOUT_WITH_POPUP_WINDOW,"Auto Logout With Popup Window")
    )


    LOCAL_PROVIDER = 'local'

    _editable_columns = ("name","userflow","logout_url","logout_method","secretkey_expireat")

    #meaningful name set in auth2, this name will be used in some other place, so change it only if necessary
    name = django_models.CharField(max_length=64,unique=True,null=True)
    #unique name returned from b2c
    idp = django_models.CharField(max_length=256,unique=True,null=False,editable=False)
    #the user flow id dedicated for this identity provider
    userflow = django_models.CharField(max_length=64,blank=True,null=True)
    #the logout url to logout the user from identity provider
    logout_url = django_models.CharField(max_length=512,blank=True,null=True)
    #the way to logout from idp
    logout_method = django_models.PositiveSmallIntegerField(choices=LOGOUT_METHODS,blank=True,null=True)
    secretkey_expireat = django_models.DateTimeField(null=True,editable=True,blank=True)
    modified = django_models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = django_models.DateTimeField(auto_now_add=timezone.now)

    class Meta:
        verbose_name_plural = "{}Identity Providers".format(" " * 9)

    @classmethod
    def get_model_change_cls(self):
        return IdentityProviderChange

    def clean(self):
        super().clean()
        self.name = self.name.strip()
        if not self.name:
            raise ValidationError("Name is empty")

    @classmethod
    def refresh_cache(cls):
        """
        Popuate the data and save them to cache
        """
        logger.debug("Refresh idp cache")
        refreshtime = timezone.localtime()
        size = 0
        idps = {}
        for obj in cls.objects.all():
            size += 1
            idps[obj.idp] = obj
            idps[obj.id] = obj
        cache.idps = (idps,size,refreshtime)
        return refreshtime

    @classmethod
    def get_idp(cls,idpid):
        """
        Return idp from cache via idp.idp or idp.id
        """
        return cache.idps.get(idpid) if idpid else None

    @classmethod
    def get_logout_url(cls,idpid):
        """
        Return idp logout url from cache
        """
        idp = cls.get_idp(idpid)
        if idp:
            return idp.logout_url
        else:
            return None

    @property
    def secretkey_expiretime(self):
        if not self.secretkey_expireat:
            return ""
        else:
            now = timezone.localtime()
            t = utils.format_datetime(self.secretkey_expireat)
            if now > self.secretkey_expireat:
                return mark_safe("<span style='background-color:darkred;color:white;padding:0px 20px 0px 20px;'>{}</span>".format(t))
            elif now + settings.SECRETKEY_EXPIREDAYS_WARNING >= self.secretkey_expireat:
                return mark_safe("<span style='background-color:#ff9966;color:white;padding:0px 20px 0px 20px;'>{}</span>".format(t))
            else:
                return mark_safe("<span style='background-color:green;color:white;padding:0px 20px 0px 20px;'>{}</span>".format(t))

    def __str__(self):
        return self.name or self.idp

class CustomizableUserflow(CacheableMixin,DbObjectMixin,django_models.Model):
    """
    Customize userflow for domain.
    The domain '*' is the default settings.
    """
    pagelayout_customized = None
    verifyemail_customized = None
    signout_customized = None

    _request_domain = None
    default_layout="""{% load i18n static %}
<table id="header" style="background:#2D2F32;width:100%;"><tr><td style="width:34%">
    <div id="logo" style="margin-left:50px;vertical-align:middle;text-align:left">
        <img src="https://{{request.get_host}}{% static "images/logo.svg" %}" style="width:318.45px;height:92px"/>
    </div>
</td><td style="width:33%">
    <div  style="vertical-align:middle;margin-left:30px;text-align:center">
        <img src="https://{{request.get_host}}{% static "images/WW4WA_White_small.png" %}" style="vertical-align:middle"/>
    </div>
</td><td style="width:33%">
</td></tr></table>
<div class="container {{container_class}}" role="presentation"  style="height:720px;padding-top:20px;padding-bottom:20px;background-image:url('https://{{request.get_host}}{% static "images/login_bg.jpg" %}');background-repeat:no-repeat;background-size:cover">
    <div class="row">
        <div class="col-lg-6">
            <div class="panel panel-default">
                <div class="panel-body">
                    <div id="api">
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<table id="header" style="background:white;width:100%;border:none;color:#999"><tr><td style="width:50%;text-align:left;vertical-align:top;padding-left:50px">
   &copy; 2020 Department of Biodiversity, Conservation and Attractions
</td><td style="width:50%;vertical-align:top;padding-right:20px;">
<div style="float:right;white-space:pre">State Operation Headquarters
17 Dick Perry Avenue Technology Park, Western Precinct
KENSINGTON Western Australia 6151
Phone: (08) 9219 9000
Email: enquiries@dbca.wa.gov.au
</div>
</td></tr></table>
    """
    default_verifyemail_from = "noreply@dbca.wa.gov.au"
    default_verifyemail_subject = "Email verification code from the Department of Biodiversity, Conservation and Attractions"

    default_verifyemail_body="""<html lang="en-gb" >
<head>
    <title>Email verification code</title>
</head>
<body>

<table width="100%" cellspacing="0" cellpadding="0" border="0">
<tbody><tr>
    <td width="50%" valign="top"></td>
    <td valign="top">
        <table dir="ltr" style="border-left:1px solid #e3e3e3;border-right:1px solid #e3e3e3" width="640" lang="en" cellspacing="0" cellpadding="0" border="0">
        <tbody>
            <tr style="background-color:#333333">
                <td style="background:#333333;border-top:1px solid #e3e3e3" width="1"></td>
                <td style="border-top:1px solid #e3e3e3;border-bottom:1px solid #e3e3e3" width="24">&nbsp;</td>
                <td style="border-top:1px solid #e3e3e3;border-bottom:1px solid #e3e3e3;padding:12px 0" width="310" valign="middle">
                    <h1 style="line-height:20pt;font-family:Segoe UI Light;font-size:18pt;color:#ffffff;font-weight:normal">
                        <span id="m_4438416264798791343HeaderPlaceholder_UserVerificationEmailHeader"><font color="White">Verify your email address</font></span>
                    </h1>
                </td>
                <td style="border-top:1px solid #e3e3e3;border-bottom:1px solid #e3e3e3" width="24">&nbsp;</td>
                </tr>
        </tbody>
        </table>

        <table dir="ltr" width="640" lang="en" cellspacing="0" cellpadding="0" border="0">
        <tbody><tr>
            <td style="background:#e3e3e3" width="1"></td>
            <td width="24">&nbsp;</td>
            <td id="m_4438416264798791343PageBody" colspan="2" style="border-bottom:1px solid #e3e3e3;padding:10px 0 20px;border-bottom-style:hidden" width="640" valign="top">
                <table cellspacing="0" cellpadding="0" border="0">
                <tbody><tr>
                    <td style="font-size:10pt;line-height:13pt;color:#000" width="630">
                        <table dir="ltr" width="100%" lang="en" cellspacing="0" cellpadding="0" border="0">
                        <tbody><tr>
                            <td>
                                <div style="font-family:'Segoe UI',Tahoma,sans-serif;font-size:14px;color:#333">
                                    <span id="m_4438416264798791343BodyPlaceholder_UserVerificationEmailBodySentence1">Thanks for verifying your <a href="mailto:ROCKY.CHEN75@gmail.com" target="_blank">{{email}}</a> account!</span>
                                </div>
                                <br>
                                <div style="font-family:'Segoe UI',Tahoma,sans-serif;font-size:14px;color:#333;font-weight:bold">
                                    <span id="m_4438416264798791343BodyPlaceholder_UserVerificationEmailBodySentence2">Your code is: {{otp}}</span>
                                </div>
                                <br>
                                <br>
                                <div style="font-family:'Segoe UI',Tahoma,sans-serif;font-size:14px;color:#333">
                                    Sincerely,
                                </div>
                                <div style="font-family:'Segoe UI',Tahoma,sans-serif;font-size:14px;font-style:italic;color:#333">
                                    dbcab2c
                                </div>
                            </td>
                        </tr></tbody>
                        </table>
                    </td>
                </tr></tbody>
                </table>
            </td>
            <td width="1">&nbsp;</td>
            <td width="1"></td>
            <td width="1">&nbsp;</td>
            <td width="1" valign="top"></td>
            <td width="29">&nbsp;</td>
            <td style="background:#e3e3e3" width="1"></td>
        </tr>
        <tr>
            <td style="background:#e3e3e3;border-bottom:1px solid #e3e3e3" width="1"></td>
            <td style="border-bottom:1px solid #e3e3e3" width="24">&nbsp;</td>
            <td id="m_4438416264798791343PageFooterContainer" colspan="6" style="border-bottom:1px solid #e3e3e3;padding:0px" width="585" valign="top"></td>
            <td style="border-bottom:1px solid #e3e3e3" width="29">&nbsp;</td>
            <td style="background:#e3e3e3;border-bottom:1px solid #e3e3e3" width="1"></td>
        </tr></tbody>
        </table>
    </td>
    <td width="50%" valign="top"></td>
</tr></tbody>
</table>

</body>
</html>"""

    default_signout_body="""{% load i18n static %}
<h4>{% if message %}{{message}}<br>{% endif %}You have signed out from Department of Biodiversity, Conservation and Attractions.
{% if idplogout %} 
    <br><br>You are still logged into the social media '{{idp}}'.
    <br><br>Please click <a href="{{idplogout}}">here</A> to log out from {{idp}} if you want.
{% endif %}
{% if relogin %} 
<br><br>If you want to log in again, please click <a href="{{relogin}}">here</A>.
{% endif %}
</h4>
"""

    _editable_columns = ("default","mfa_set","mfa_reset","password_reset","page_layout","fixed","extracss","verifyemail_from","verifyemail_subject","verifyemail_body","signedout_url","relogin_url","signout_body","sortkey")

    domain = django_models.CharField(max_length=128,null=False,help_text=help_text_domain)
    fixed = django_models.CharField(max_length=64,null=True,blank=True,help_text="The only user flow used by this domain if configured")
    default = django_models.CharField(max_length=64,null=True,blank=True,help_text="The default user flow used by this domain")
    mfa_set = django_models.CharField(max_length=64,null=True,blank=True,help_text="The mfa set user flow")
    mfa_reset = django_models.CharField(max_length=64,null=True,blank=True,help_text="The mfa reset user flow")
    password_reset = django_models.CharField(max_length=64,null=True,blank=True,help_text="The user password reset user flow")

    extracss = django_models.TextField(null=True,blank=True)
    page_layout = django_models.TextField(null=True,blank=True)

    verifyemail_from = django_models.EmailField(null=True,blank=True)
    verifyemail_subject = django_models.CharField(max_length=512,null=True,blank=True)
    verifyemail_body = django_models.TextField(null=True,blank=True)

    signedout_url = django_models.CharField(max_length=256,null=True,blank=True,help_text="Redirect to this url after sign out from sso")
    relogin_url = django_models.CharField(max_length=256,null=True,blank=True,help_text="A link can be used in signed out page to let user relogin to the system after signout from sso.")
    signout_body = django_models.TextField(null=True,blank=True,help_text="The body template used in the signed out page")

    sortkey = django_models.CharField(max_length=128,editable=True,help_text="A sorting string consisted with a 2 digitals and string separated by ':', the sorting string is auto generated if the digitals is in {}".format(RequestDomain.all_base_sort_keys()))

    modified = django_models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = django_models.DateTimeField(auto_now_add=timezone.now)

    class Meta:
        verbose_name_plural = "{}Customizable Userflows".format(" " * 10)

    @classmethod
    def get_model_change_cls(self):
        return CustomizableUserflowChange

    @property
    def is_default(self):
        """
        Return True if the current object is the default userflow
        """
        return self.domain == '*'

    @property
    def request_domain(self):
        if self._request_domain is None:
            self._request_domain = RequestDomain.get_instance(self.domain)

        return self._request_domain

    def clean(self):
        """
        Validate the changed data
        """
        super().clean()

        request_domain = RequestDomain.get_instance(self.domain)
        if not request_domain:
            raise ValidationError("Please configure domain.")
        self.domain = request_domain.config
        try:
            if not self.sortkey or RequestDomain.is_base_sort_key(int(self.sortkey.split(":",1)[0])):
                self.sortkey = request_domain.sort_key
            else:
                basekey,key = self.sortkey.split(":",1)
                basekey = int(basekey)
                if basekey > 99 or basekey < 0:
                    #basekey should between 0 99
                    self.sortkey = request_domain.sort_key
                else:
                    self.sortkey = "{:0>2}:{}".format(basekey,key)
        except:
            #A wrong sort key
            self.sortkey = request_domain.sort_key


        if self.domain == "*":
            #default userflow
            if not self.page_layout:
                #set the page layout to default page layout if it is empty
                self.page_layout = self.default_layout
            if not self.verifyemail_body:
                #set the verify email body to the default body if it is emtpy
                self.verifyemail_body = self.default_verifyemail_body
            if not self.verifyemail_from:
                self.verifyemail_from = self.default_verifyemail_from
            if not self.verifyemail_subject:
                self.verifyemail_subject = self.default_verifyemail_subject
            if not self.signout_body:
                self.signout_body = self.default_signout_body

            #check the required fields
            invalid_columns = []
            for name in ("default","mfa_set","mfa_reset","password_reset","page_layout","verifyemail_from","verifyemail_subject","verifyemail_body"):
                if not getattr(self,name):
                    invalid_columns.append(name)
            if len(invalid_columns) == 1:
                raise ValidationError("The property({}) can't be empty for global settings.".format(invalid_columns[0]))
            elif len(invalid_columns) > 1:
                raise ValidationError("The properties({}) can't be empty for global settings.".format(invalid_columns))

    def __str__(self):
        return self.domain

    @classmethod
    def get_userflow(cls,domain):
        """
        Get userflow from the cache
        """
        return cache.get_userflow(domain)

    @classmethod
    def find_userflows(cls,domain):
        """
        Find matched userflows in order from the cache
        """
        return cache.find_userflows(domain)

    @classmethod
    def refresh_cache(cls):
        """
        Populate the cached data and save them to cache
        """
        logger.debug("Refresh Customizable Userflow cache")
        userflows = []
        defaultuserflow = None
        refreshtime = timezone.localtime()
        size = 0
        for o in cls.objects.all().order_by(sortkey_c.asc()):
            if o.is_default:
                defaultuserflow = o

            userflows.append(o)

            size += 1

        if not defaultuserflow :
            raise Exception("The default customizable userflow configuration is missing.")
        else:
            if not defaultuserflow.page_layout:
                defaultuserflow.page_layout = cls.default_layout
            if not defaultuserflow.extracss is None:
                defaultuserflow.extracss = ""

            if not defaultuserflow.verifyemail_body:
                defaultuserflow.verifyemail_body = cls.default_verifyemail_body
            if not defaultuserflow.verifyemail_from:
                defaultuserflow.verifyemail_from = cls.default_verifyemail_from
            if not defaultuserflow.verifyemail_subject:
                defaultuserflow.verifyemail_subject = cls.default_verifyemail_subject

            if not defaultuserflow.signout_body:
                defaultuserflow.signout_body = cls.default_signout_body

        for o in userflows:
            if o != defaultuserflow:
                o.defaultuserflow = defaultuserflow
                for name in ("fixed","default","mfa_set","mfa_reset","password_reset"):
                    if not getattr(o,name):
                        setattr(o,name,getattr(defaultuserflow,name))

            else:
                o.defaultuserflow = None

        cache.userflows = (userflows,defaultuserflow,size,refreshtime)
        return refreshtime


class UserEmail(object):
    """
    User email configuration.
    """
    match_all = False
    def __init__(self,config):
        self.config = config
        self.sort_key = "{}:{}".format(self.base_sort_key,config)

    all_email_re = re.compile("^\\*+(@\\*+)?$")
    @classmethod
    def get_instance(cls,email):
        email = email.strip() if email else None
        if not email:
            return None
        email = email.lower()
        if cls.all_email_re.search(email):
            return AllUserEmail()
        if "@" not in email:
            raise ValidationError("The email config({}) is invalid".format(email))
        if email[0] == "@":
            if "*" in email:
                raise ValidationError("The domain of the email config({}) can't contain '*'".format(email))
            else:
                return DomainEmail(email)
        elif email[0] == '^' and email[-1] == '$':
            return RegexUserEmail(email)
        elif "*" in email:
            return UserEmailPattern(email)
        else:
            return ExactUserEmail(email)

    def match(self,email):
        return False

class AllUserEmail(UserEmail):
    base_sort_key = 2

    def __init__(self):
        super().__init__("*")
        self.match_all = True

    def match(self,email):
        return True

    @property
    def qs_filter(self):
        return None

    def contain(self,useremail):
        return True

class ExactUserEmail(UserEmail):
    base_sort_key = 8

    def match(self,email):
        return self.config == email

    @property
    def qs_filter(self):
        return django_models.Q(email=self.config)

    def contain(self,useremail):
        if isinstance(useremail,RegexUserEmail):
            return None
        return self.config == useremail.config

class DomainEmail(UserEmail):
    base_sort_key = 4

    def match(self,email):
        return email.endswith(self.config)

    @property
    def qs_filter(self):
        return django_models.Q(email__endswith=self.config)

    def contain(self,useremail):
        if isinstance(useremail,AllUserEmail):
            return False
        elif isinstance(useremail,ExactUserEmail):
            return self.match(useremail.config)
        elif isinstance(useremail,DomainEmail):
            return self.config == useremail.config
        elif isinstance(useremail,RegexUserEmail):
            return None
        else:
            return useremail.config.endswith(self.config)

class RegexUserEmail(UserEmail):
    base_sort_key = 5
    def __init__(self,email):
        super().__init__(email)
        try:
            self._qs_re = r"{}".format(email)
            self._re = re.compile(self._qs_re)
        except Exception as ex:
            raise ValidationError("The regex email config({}) is invalid.{}".format(email,str(ex)))

    def match(self,email):
        return True if self._re.search(email) else False

    @property
    def qs_filter(self):
        return django_models.Q(email__regex=self._qs_re)

    def contain(self,useremail):
        return None

class UserEmailPattern(UserEmail):
    base_sort_key = 6
    def __init__(self,email):
        super().__init__(email)
        try:
            self._qs_re = r"^{}$".format(email.replace(".","\\.").replace('*','[a-zA-Z0-9\\._\\-\\+]*'))
            self._re = re.compile(self._qs_re)
        except Exception as ex:
            raise ValidationError("The regex email config({}) is invalid.{}".format(email,str(ex)))

    def match(self,email):
        return True if self._re.search(email) else False

    @property
    def qs_filter(self):
        return django_models.Q(email__regex=self._qs_re)

    def contain(self,useremail):
        if isinstance(useremail,AllUserEmail):
            return False
        elif isinstance(useremail,ExactUserEmail):
            return self.match(useremail.config)
        elif isinstance(useremail,RegexUserEmail):
            return None
        else:
            if isinstance(useremail,DomainEmail):
                useremail = UserEmail.get_instance("*{}".format(useremail.config))
            p_index = 0
            p_star_index = -1
            c_index = 0
            p_char = None
            c_char = None
            while c_index < len(useremail.config):
                p_char = self.config[p_index] if p_index < len(self.config) else None
                c_char = useremail.config[c_index]
                if p_star_index == len(self.config) - 1:
                    #last char is '*'
                    return True
                elif p_char == '*':
                    p_star_index = p_index
                    p_index += 1
                    if c_char == '*':
                        c_index += 1
                elif c_char == '*':
                    if p_star_index >= 0:
                        p_index = p_star_index + 1
                        c_index += 1
                    else:
                        return False
                elif p_char == c_char:
                    p_index += 1
                    c_index += 1
                elif p_star_index >= 0:
                    p_index = p_star_index + 1
                    c_index += 1
                else:
                    return False

            return p_index >= len(self.config)

class UserGroup(CacheableMixin,DbObjectMixin,django_models.Model):
    _useremails = None
    _excluded_useremails = None

    _editable_columns = ("users","parent_group","excluded_users","identity_provider","groupid","session_timeout")

    name = django_models.CharField(max_length=32,unique=True,null=False)
    groupid = django_models.SlugField(max_length=32,null=False,blank=True)
    parent_group = django_models.ForeignKey('self', on_delete=django_models.SET_NULL,null=True,blank=True)
    users = ArrayField(django_models.CharField(max_length=64,null=False),help_text=help_text_users)
    excluded_users = ArrayField(django_models.CharField(max_length=64,null=False),null=True,blank=True,help_text=help_text_users)
    identity_provider = django_models.ForeignKey(IdentityProvider, on_delete=django_models.SET_NULL,null=True,blank=True,limit_choices_to=~django_models.Q(idp__exact=IdentityProvider.AUTH_EMAIL_VERIFY[0]))
    session_timeout = django_models.PositiveSmallIntegerField(null=True,editable=True,blank=True,help_text="Session timeout in seconds, 0 means never timeout")
    modified = django_models.DateTimeField(editable=False,db_index=True)
    created = django_models.DateTimeField(auto_now_add=timezone.now)

    class Meta:
        unique_together = [["users","excluded_users"]]
        verbose_name_plural = "{}User Groups".format(" " * 12)


    @property
    def sessiontimeout(self):
        if self.session_timeout is not None:
            return self.session_timeout
        elif self.parent_group_id is not None:
            return (cache.usergroups.get(self.parent_group_id) or self.parent_group).sessiontimeout
        else:
            return 0


    @classmethod
    def get_model_change_cls(self):
        return UserGroupChange

    @classmethod
    def get_session_timeout(cls,usergroups):
        """
        Return the session timeout from groups.
        """
        timeout = 0
        for group in usergroups:
            t = group.sessiontimeout
            if not t:
                return t
            if timeout < t:
                timeout = t

        return timeout

    @classmethod
    def get_groupnames(cls,usergroups):
        """
        return groupname string seprated by "," based on usergroups
        """
        groupnames = []
        index = 0
        for usergroup in usergroups:
            group = usergroup
            index = len(groupnames)
            while group:
                if group.groupid in groupnames:
                    break
                if group.groupid:
                    groupnames.insert(index,group.groupid)
                group = group.parent_group
        return ",".join(groupnames)

    def is_changed(self,update_fields=None):
        changed = super().is_changed(update_fields)
        if changed:
            self.modified = timezone.localtime()
            return True
        else:
            return self.name != self.db_obj.name

    def clean(self):
        super().clean()
        self.name = self.name.strip()
        if not self.name:
            raise ValidationError("Name is empty")

        user_emails = self.get_useremails(self.users)
        if user_emails:
            self.users = [u.config for u in user_emails]
        else:
            self.users = ["*"]

        user_emails = self.get_useremails(self.excluded_users)
        if user_emails:
            self.excluded_users = [u.config for u in user_emails]
        else:
            self.excluded_users = None

        if not self.parent_group and not self.is_public_group:
            self.parent_group = self.public_group()

        #check whether the parent group  is the group itself or is the descendant of itself
        if self.id:
            pgroup = self.parent_group
            while pgroup:
                if pgroup.id == self.id:
                    if pgroup.id == self.parent_group.id:
                        raise ValidationError("The parent group of the group ({0}) can't be itself".format(self.name))
                    else:
                        raise ValidationError("The parent group({1}) of the group ({0}) can't be descendant of the group({0})".format(self.name,self.parent_group.name))
                pgroup = pgroup.parent_group

        #check whether excluded_users is contained by users
        for excluded_useremail in self.excluded_useremails:
            contained = False
            for useremail in self.useremails:
                if useremail.contain(excluded_useremail) is not False:
                    contained = True
                    break
            if not contained:
                raise ValidationError("The excluded email pattern({}) is not contained by email patterns configured in current group({})".format(excluded_useremail.config,self))
        #check between current group and parent group
        if self.parent_group:
            #check whether user eamil in this group is contained by parent group
            for useremail in self.useremails:
                contained = False
                for parent_useremail in self.parent_group.useremails:
                    if parent_useremail.contain(useremail) is not False:
                        contained = True
                        break
                if not contained:
                    raise ValidationError("The email pattern({}) in the current group({}) is not contained by the parent group({})".format(useremail.config,self,self.parent_group))
            #check whether excluded user email in parent group is not contained by this group
            for parent_excluded_useremail in self.parent_group.excluded_useremails:
                contained = False
                for useremail in self.useremails:
                    if useremail.contain(parent_excluded_useremail) :
                        contained = True
                        break
                if not contained:
                    continue

                contained = False
                for excluded_useremail in self.excluded_useremails:
                    if excluded_useremail.contain(parent_excluded_useremail) is not False:
                        contained = True
                        break
                if not contained:
                    raise ValidationError("The excluded email pattern({}) in the parent group({}) is contained by the current group({})".format(parent_excluded_useremail.config,self.parent_group,self))

        #check between current group and children group
        if self.id:
            for child_group in UserGroup.objects.filter(parent_group=self):
                #check whether user email in child group is contained by this group
                for child_useremail in child_group.useremails:
                    contained = False
                    for useremail in self.useremails:
                        if useremail.contain(child_useremail) is not False:
                            contained = True
                            break
                    if not contained:
                        raise ValidationError("The email pattern({}) in the child group({}) is not contained by the current group({})".format(child_useremail.config,child_group,self))

                #check whether excluded user eamil in this group is not contained by child group
                for excluded_useremail in self.excluded_useremails:
                    contained = False
                    for child_useremail in child_group.useremails:
                        if child_useremail.contain(excluded_useremail):
                            contained = True
                            break
                    if not contained:
                        continue

                    contained = False
                    for child_excluded_useremail in child_group.excluded_useremails:
                        if child_excluded_useremail.contain(excluded_useremail) is not False:
                            contained = True
                            break
                    if not contained:
                        raise ValidationError("The excluded email pattern({}) in the current group({}) is contained by the child group({})".format(excluded_useremail.config,self,child_group))

    @property
    def is_public_group(self):
        return self == cache.public_group

    def is_group(self,usergroup):
        """
        Return True if group is usergroup or a descendant of usergroup ;otherwise return False
        """
        group = self
        while group:
            if group == usergroup:
                return True
            else:
                group = group.parent_group

        return False

    def get_useremails(self,users):
        if users:
            user_emails = []
            for user in users:
                try:
                    user_email = UserEmail.get_instance(user)
                    if not user_email:
                        continue
                    user_emails.append(user_email)
                except:
                    continue
            user_emails.sort(key=lambda o:o.sort_key)
            match_all_user = next((u for u in user_emails if u.match_all),None)
            if match_all_user:
                return [match_all_user]
            else:
                return user_emails
        else:
            return []

    @property
    def useremails(self):
        if not self._useremails:
            self._useremails = self.get_useremails(self.users)
        return self._useremails

    @property
    def excluded_useremails(self):
        if not self._excluded_useremails:
            self._excluded_useremails = self.get_useremails(self.excluded_users)
        return self._excluded_useremails

    def __str__(self):
        return self.name

    @classmethod
    def refresh_cache(cls):
        logger.debug("Refresh UserGroup cache")
        group_trees = {}
        refreshtime = timezone.localtime()
        size = 0
        dbca_group = None
        public_group = None
        groups = {}
        for group in cls.objects.all():
            size += 1
            group_trees[group.id] = (group,[])
            groups[group.id] = group
            if group.groupid == settings.DBCA_STAFF_GROUPID:
                dbca_group = group
            if group.users == ["*"] and group.excluded_users is None:
                public_group = group

        if not public_group and group_trees:
            raise Exception("Missing user group 'Public User'")
        #build the tree
        for key,val in group_trees.items():
            group,subgroups = val
            if group.parent_group_id:
                group_trees[group.parent_group_id][1].append(val)
        group_trees = [v for v in group_trees.values() if not v[0].parent_group_id]
        cache.usergrouptree = (group_trees,groups,public_group,dbca_group,size,refreshtime)
        return refreshtime

    @classmethod
    def get_grouptree(cls):
        return cache.usergrouptree

    @classmethod
    def dbca_group(cls):
        return cache.dbca_group

    def usercategories(cls):
        return cache.usergrouptree[0][1]

    @classmethod
    def public_group(cls):
        return cache.public_group

    @classmethod
    def public_groupid(cls):
        return cache.public_group.id

    @classmethod
    def get_group(cls,pk):
        """
        Return cached group if found; otherwise return None
        """
        return cache.usergroups[pk]

    def contain(self,email):
        """
        Return True if email belongs to this group; otherwise return False
        """
        matched = False
        check_useremail_first = (len(self.useremails) <= len(self.excluded_useremails)) if self.excluded_useremails else True
        if check_useremail_first:
            matched = False
            for useremail in self.useremails:
                if useremail.match(email):
                    #email is included in the useremails
                    matched = True
                    break
    
            if not matched:
                return False

            if self.excluded_useremails:
                for useremail in self.excluded_useremails:
                    if useremail.match(email):
                        #email is excluded in the excluded_useremails
                        return False
            return True
        else:
            for useremail in self.excluded_useremails:
                if useremail.match(email):
                    #email is excluded in the excluded_useremails
                    return False
            
            for useremail in self.useremails:
                if useremail.match(email):
                    #email is included in the useremails
                    return True

            return False

    @classmethod
    def find_groups(cls,email,cacheable=True):
        """
        email should be in lower case
        Return a tuple(the matched user groups,group names); if not found, return ([],"")
        """
        def _add_group(groups,group):
            index = len(groups) - 1
            added = False
            while index >= 0:
                if groups[index].is_group(group):
                    #already added
                    added = True
                    break
                elif group.parent_group.is_group(groups[index]):
                    groups[index] = group
                    added =  True
                    break
                index -= 1
            if not added:
                groups.append(group)

        usergroups = cache.get_email_groups(email)
        if not usergroups:
            trees = list(cls.get_grouptree())
            usergroups = []
            while trees:
                matched = False
                #try to find a matched group from the trees
                group,subgroups = trees.pop(0)
                matched = group.contain(email)
                if matched:
                    if subgroups:
                        for subgroup in subgroups:
                            trees.append(subgroup)
                    else:
                        _add_group(usergroups,group)

                elif group.parent_group :
                    _add_group(usergroups,group.parent_group)
            if usergroups:
                usergroups = (usergroups,cls.get_groupnames(usergroups))
                if cacheable:
                    cache.set_email_groups(email,usergroups)
            else:
                usergroups = (usergroups,"")


        return usergroups

    @classmethod
    def get_identity_provider(cls,email):
        email = email.lower()
        groups = cls.find_groups(email)[0]
        for group in groups:
            while group:
                if group.identity_provider:
                    return group.identity_provider
                else:
                    group = group.parent_group

        return None

class RequestPath(object):
    match_all = False

    def __init__(self,config):
        self.config = config
        self.sort_key = "{}:{}".format(self.base_sort_key,config)

    all_path_re = re.compile("^\\*+$")
    @classmethod
    def get_instance(cls,config):
        config = config.strip() if config else None
        if not config:
            return None

        if cls.all_path_re.search(config):
            return AllRequestPath()

        if config[0] == '=':
            path = config[1:].strip()
            if path[0] == '/':
                config = "={}".format(path)
            else:
                path = "/{}".format(path)
                config = "={}".format(path)

            return ExactRequestPath(config,path)
        elif config[0] == '^' :
            return RegexRequestPath(config,flags=re.IGNORECASE)
        else:
            if config[0] != '/':
                config = "/{}".format(config)
            return PrefixRequestPath(config)

    def match(self,path):
        return False

class AllRequestPath(RequestPath):
    base_sort_key = 1

    def __init__(self):
        super().__init__("*")
        self.match_all = True

    def match(self,email):
        return True

class ExactRequestPath(RequestPath):
    base_sort_key = 8
    def __init__(self,config,path):
        super().__init__(config)
        self._path = path

    def match(self,path):
        return self._path == path

class PrefixRequestPath(RequestPath):
    base_sort_key = 3

    def __init__(self,config):
        super().__init__(config)
        if self.config == "/":
            self.match_all = True

    def match(self,path):
        if not path:
            return False

        return path.startswith(self.config)

class RegexRequestPath(RequestPath):
    base_sort_key = 6
    def __init__(self,path,flags=None):
        super().__init__(path)
        try:
            self._re = re.compile(path,flags)
        except Exception as ex:
            raise ValidationError("The regex path config({}) is invalid.{}".format(path,str(ex)))
        if self.config in ("^.*$",):
            self.match_all = True

    def match(self,path):
        if not path:
            return False

        return True if self._re.search(path) else False


class AuthorizationMixin(DbObjectMixin,django_models.Model):

    _request_domain = None
    _excluded_request_paths = None
    _request_paths = None

    _allow_all = None
    _deny_all = None

    _editable_columns = ("domain","paths","excluded_paths")

    domain = django_models.CharField(max_length=128,null=False,help_text=help_text_domain)
    paths = ArrayField(django_models.CharField(max_length=512,null=False),null=True,blank=True,help_text=help_text_paths)
    excluded_paths = ArrayField(django_models.CharField(max_length=128,null=False),null=True,blank=True,help_text=help_text_paths)
    sortkey = django_models.CharField(max_length=128,editable=False)
    modified = django_models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = django_models.DateTimeField(auto_now_add=timezone.now)

    class Meta:
        abstract = True

    @property
    def allow_all(self):
        if self._allow_all is None:
            if (not self.request_paths or any(p.match_all for p in self.request_paths)) and not self.excluded_request_paths:
                self._allow_all = True
            else:
                self._allow_all = False

        return self._allow_all

    @property
    def deny_all(self):
        if self._deny_all is None:
            if self.excluded_request_paths and any(p.match_all for p in self.excluded_request_paths):
               self._deny_all = True
            else:
               self._deny_all = False

        return self._deny_all

    def clean(self):
        super().clean()
        request_domain = RequestDomain.get_instance(self.domain)
        if not request_domain:
            raise ValidationError("Please configure domain.")
        self.domain = request_domain.config
        self.sortkey = request_domain.sort_key

        request_paths = self.get_request_paths(self.paths)
        if not request_paths:
            self.paths = None
        else:
            self.paths = [p.config for p in request_paths]
        """
        elif isinstance(request_domain,ExactRequestDomain) or any(p.match_all for p in request_paths):
            self.paths = [p.config for p in request_paths]
        else:
            raise ValidationError("A domain pattern only supports empty path or all path")
        """

        excluded_request_paths = self.get_request_paths(self.excluded_paths)
        if not excluded_request_paths:
            self.excluded_paths = None
        else:
            self.excluded_paths = [p.config for p in excluded_request_paths]
        """
        elif isinstance(request_domain,ExactRequestDomain) or any(p.match_all for p in excluded_request_paths):
            self.excluded_paths = [p.config for p in excluded_request_paths]
        else:
            raise ValidationError("A domain pattern only supports empty excluded path or all excluded path")
        """

    @property
    def request_domain(self):
        if self._request_domain is None:
            self._request_domain = RequestDomain.get_instance(self.domain)

        return self._request_domain

    def get_request_paths(self,paths):
        if not paths:
            return []

        request_paths = []
        for path in paths:
            try:
                request_path = RequestPath.get_instance(path)
                if not request_path:
                    continue
                request_paths.append(request_path)
            except:
                continue
        request_paths.sort(key=lambda o:o.sort_key)
        match_all_path = next((p for p in request_paths if p.match_all),None)
        if match_all_path:
            #contain one match all path, ignore other paths
            return [match_all_path]
        else:
            return request_paths


    @property
    def request_paths(self):
        if self._request_paths is None:
            self._request_paths = self.get_request_paths(self.paths)

        return self._request_paths

    @property
    def excluded_request_paths(self):
        if self._excluded_request_paths is None:
            self._excluded_request_paths = self.get_request_paths(self.excluded_paths)

        return self._excluded_request_paths

    def allow(self,path):
        if self.allow_all:
            return True
        elif self.deny_all:
            return False

        if self.request_paths:
            matched = False
            for request_path in self.request_paths:
                if request_path.match(path):
                    matched = True
                    break
            if not matched:
                return False

        if not self.excluded_request_paths:
            return True

        for request_path in self.excluded_request_paths:
            if request_path.match(path):
                return False

        return True

    @staticmethod
    def find_authorizations(email,domain):
        """
        email should be in lower case
        domain should be in lower case
        return  a list of matched UserAuthorization or UserGroupAuthorization;return [] if can't found
        """

        """
        #try to find the matched userauthorization
        userauthorizations = UserAuthorization.get_authorizations(email)
        if userauthorizations:
            for authorization in userauthorizations:
                if authorization.request_domain.match(domain):
                    return [authorization]
        """

        #try to find the matched usergroupauthorization
        matched_authorizations = []
        usergroups = UserGroup.find_groups(email)[0]

        matched = False
        for usergroup in usergroups:
            checkgroup = usergroup
            while checkgroup:
                authorizations = UserGroupAuthorization.get_authorizations(checkgroup)
                matched = False
                if authorizations:
                    for authorization in authorizations:
                        if authorization.request_domain.match(domain):
                            if authorization.deny_all:
                                matched = True
                                break
                            elif authorization.allow_all:
                                return [authorization]
                            else:
                                matched_authorizations.append(authorization)
                                matched = True
                                break
                if matched:
                    break
                else:
                    checkgroup = checkgroup.parent_group

        return matched_authorizations

    @staticmethod
    def find_all_authorizations(email,domain):
        """
        email should be in lower case
        domain should be in lower case
        return   a list of tuple (usergroup, authorizationgroup,authorization)
        """

        #try to find the matched usergroupauthorization
        matched_authorizations = []
        usergroups = UserGroup.find_groups(email)[0]

        matched = False
        for usergroup in usergroups:
            checkgroup = usergroup
            while checkgroup:
                authorizations = UserGroupAuthorization.get_authorizations(checkgroup)
                matched = False
                if authorizations:
                    for authorization in authorizations:
                        if authorization.request_domain.match(domain):
                            matched_authorizations.append((usergroup,checkgroup,authorization))
                            matched = True
                            break
                if matched:
                    break
                else:
                    if not checkgroup.parent_group:
                        matched_authorizations.append((usergroup,checkgroup,None))
                        break
                    else:
                        checkgroup = checkgroup.parent_group

        return matched_authorizations

def check_authorization(email,domain,path):
    """
    Return True if the user(email) can access domain/path; otherwise return False
    """
    email = email.lower()
    domain = domain.lower()
    authorizations = AuthorizationMixin.find_all_authorizations(email,domain)
    if authorizations:
        result = []
        allow = False
        for o in authorizations:
            if path.startswith("/sso/"):
                result.append((o[0],o[1],True))
                allow = True
            elif not o[2]:
                result.append((o[0],o[1],False))
            elif o[2].allow(path):
                result.append((o[0],o[1],True))
                allow = True
            else:
                result.append((o[0],o[1],False))
        return (allow,result)
    else:
        return (False,[])

def can_access(email,domain,path):
    """
    Return True if the user(email) can access domain/path; otherwise return False
    """
    email = email.lower()
    domain = domain.lower()
    groupskey = cache.get_email_groupskey(email)
    if not groupskey:
        #this method will find email's groups and cache in memory via two maps(email to gorupskey, groupskey to groups)
        usergroups = UserGroup.find_groups(email)[0]
        if not usergroups:
            #Not in any user group. can't access
            return False

        #groupskey is already set by find_groups
        groupskey = cache.get_email_groupskey(email)

    authorizations = cache.get_authorizations(groupskey,domain)
    if authorizations is None:
        authorizations = AuthorizationMixin.find_authorizations(email,domain)
        cache.set_authorizations(groupskey,domain,authorizations)
    if authorizations:
        return any(obj.allow(path) for obj in authorizations)
    else:
        return False

class UserAuthorization(CacheableMixin,AuthorizationMixin):
    user = django_models.EmailField(max_length=64)

    class Meta:
        unique_together = [["user","domain"]]
        verbose_name_plural = "{}User Authorizations".format(" " * 7)

    @classmethod
    def get_model_change_cls(self):
        return UserAuthorizationChange

    def clean(self):
        super().clean()
        self.user = self.user.strip().lower() if self.user else None
        if not self.user:
            raise ValidationError("Useremail is empty")

    @classmethod
    def refresh_cache(cls):
        logger.debug("Refresh UserAuthorization cache")
        userauthorization = {}
        previous_user = None
        size = 0
        refreshtime = timezone.localtime()
        for authorization in UserAuthorization.objects.all().order_by("user",sortkey_c.asc()):
            size += 1

            if not previous_user:
                userauthorization[authorization.user] = [authorization]
                previous_user = authorization.user
            elif previous_user == authorization.user:
                userauthorization[authorization.user].append(authorization)
            else:
                userauthorization[authorization.user] = [authorization]
                previous_user = authorization.user

        cache.userauthorization = (userauthorization,size,refreshtime)
        return refreshtime

    @classmethod
    def get_authorizations(cls,useremail):
        return cache.userauthorization.get(useremail)

    def __str__(self):
        return self.user

class UserGroupAuthorization(CacheableMixin,AuthorizationMixin):
    usergroup = django_models.ForeignKey(UserGroup, on_delete=django_models.CASCADE)

    class Meta:
        unique_together = [["usergroup","domain"]]
        verbose_name_plural = "{}User Group Authorizations".format(" " * 11)

    @classmethod
    def get_model_change_cls(self):
        return UserGroupAuthorizationChange

    @classmethod
    def refresh_cache(cls):
        logger.debug("Refresh UserGroupAuthorization cache")
        usergroupauthorization = {}
        previous_usergroup = None
        size = 0
        refreshtime = timezone.localtime()
        for authorization in UserGroupAuthorization.objects.all().order_by("usergroup","sortkey"):
            size += 1
            #try to get the data from cache to avoid a extra db access
            try:
                authorization.usergroup = cache.usergroups[authorization.usergroup_id]
            except:
                pass

            if not previous_usergroup:
                usergroupauthorization[authorization.usergroup] = [authorization]
                previous_usergroup = authorization.usergroup
            elif previous_usergroup == authorization.usergroup:
                usergroupauthorization[authorization.usergroup].append(authorization)
            else:
                usergroupauthorization[authorization.usergroup] = [authorization]
                previous_usergroup = authorization.usergroup

        cache.usergroupauthorization = (usergroupauthorization,size,refreshtime)
        return refreshtime

    @classmethod
    def get_authorizations(cls,usergroup):
        return cache.usergroupauthorization.get(usergroup)

    def __str__(self):
        return str(self.usergroup)

class SystemUserManager(UserManager):
    def get_queryset(self):
        return super().get_queryset().filter(systemuser=True)

class NormalUserManager(UserManager):
    def get_queryset(self):
        return super().get_queryset().filter(systemuser=False)

class User(AbstractUser):
    last_idp = django_models.ForeignKey(IdentityProvider, on_delete=django_models.SET_NULL,editable=False,null=True)
    systemuser = django_models.BooleanField(default=False,editable=False)
    comments = django_models.TextField(null=True,editable=True,blank=True)
    modified = django_models.DateTimeField(auto_now=timezone.now)

    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'
        db_table = "auth_user"
        verbose_name_plural = "{}Users".format(" " * 14)
        unique_together = [["email"]]

    def clean(self):
        super().clean()
        self.email = self.email.strip().lower() if self.email else None
        if not self.email:
            raise ValidationError("Email is empty")

        if not self.username:
            self.username = self.email

        if not self.id:
            self.is_active = True

        usergroups = UserGroup.find_groups(self.email)[0]

        dbcagroup = UserGroup.dbca_group()
        if dbcagroup and any(usergroup.is_group(dbcagroup) for usergroup in usergroups):
            self.is_staff = True

    def __str__(self):
        return self.email

class UserToken(django_models.Model):
    DISABLED = -1
    NOT_CREATED = -2
    EXPIRED = -3
    GOOD = 1
    WARNING = 2

    RANDOM_CHARS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYA0123456789~!@#$%^&*()-_+=`{}[];':\",./<>?"
    RANDOM_CHARS_MAX_INDEX = len(RANDOM_CHARS) - 1

    user = django_models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=django_models.CASCADE,primary_key=True,related_name="token",editable=False)
    enabled = django_models.BooleanField(default=False,editable=False)
    token = django_models.CharField(max_length=128,null=True,editable=False)
    created = django_models.DateTimeField(null=True,editable=False)
    expired = django_models.DateField(null=True,editable=False)
    modified = django_models.DateTimeField(editable=False,db_index=True,auto_now=True)

    class Meta:
        verbose_name_plural = "{}Access Tokens".format(" " * 8)

    def __str__(self):
        return self.user.email

    @classmethod
    def generate_user_secret(cls):
        return "".join(cls.RANDOM_CHARS[random.randint(0,cls.RANDOM_CHARS_MAX_INDEX)] for i in range(0,32))

    @property
    def is_expired(self):
        if not self.token:
            return True
        elif self.expired:
            return timezone.localdate() > self.expired
        else:
            return False
    @property
    def html_statusname(self):
        if not self.enabled:
            return mark_safe("<span style='background-color:darkred;color:white;padding:0px 20px 0px 20px;'>Disabled</span>")
        elif not self.token:
            return ""
        elif not self.expired:
            return mark_safe("<span style='background-color:green;color:white;padding:0px 20px 0px 20px;'>Expired at : 2099-12-31</span>")
        else:
            today = timezone.localdate()
            t = self.expired.strftime("%Y-%m-%d")
            if today > self.expired:
                return mark_safe("<span style='background-color:darkred;color:white;padding:0px 20px 0px 20px;'>Expired at : {}</span>".format(t))
            elif not settings.USER_ACCESS_TOKEN_WARNING:
                return mark_safe("<span style='background-color:green;color:white;padding:0px 20px 0px 20px;'>Expired at : {}</span>".format(t))
            elif today + settings.USER_ACCESS_TOKEN_WARNING >= self.expired:
                return mark_safe("<span style='background-color:#ff9966;color:white;padding:0px 20px 0px 20px;'>Expired at : {}</span>".format(t))
            else:
                return mark_safe("<span style='background-color:green;color:white;padding:0px 20px 0px 20px;'>Expired at : {}</span>".format(t))


    @property
    def status(self):
        if not self.enabled:
            return self.DISABLED
        elif not self.token:
            return self.NOT_CREATED
        elif not self.expired:
            return self.GOOD
        else:
            today = timezone.localdate()
            if today > self.expired:
                return self.EXPIRED
            elif not settings.USER_ACCESS_TOKEN_WARNING:
                return self.GOOD
            elif today + settings.USER_ACCESS_TOKEN_WARNING >= self.expired:
                return self.WARNING
            else:
                return self.GOOD

    def is_valid(self,token):
        if not self.enabled or not self.token or self.token != token:
            return False
        elif self.is_expired:
            return False
        else:
            return True

    def generate_token(self,token_lifetime=None):
        """
        generate an access token
        token_life_time: days
        permanent: create permanent token if True
        """
        self.created = timezone.localtime()
        if not token_lifetime or token_lifetime <= 0:
            self.expired = None
        else:
            self.expired = self.created.date() + timedelta(days=token_lifetime)
        self.token = hashlib.sha256('{}|{}|{}|{}|{}|{}|{}|{}'.format(self.user.email.lower(),self.user.is_superuser,self.user.is_staff,self.user.is_active,self.created.timestamp(),self.expired.isoformat() if self.expired else "2099-12-31",settings.SECRET_KEY,self.generate_user_secret()).encode('utf-8')).hexdigest()

    def save(self,*args,**kwargs):
        with transaction.atomic():
            super().save(*args,**kwargs)

class UserTOTP(django_models.Model):
    email = django_models.CharField(max_length=64,null=False,editable=False,unique=True)
    secret_key = django_models.CharField(max_length=512,null=False,editable=False)
    timestep = django_models.PositiveSmallIntegerField(null=False,editable=False)
    prefix = django_models.CharField(max_length=64,null=False,editable=False)
    issuer = django_models.CharField(max_length=64,null=False,editable=False)
    name = django_models.CharField(max_length=128,null=False,editable=False)
    algorithm = django_models.CharField(max_length=32,null=False,editable=False)
    digits = django_models.PositiveSmallIntegerField(null=False,editable=False)
    last_verified_code = django_models.CharField(max_length=16,null=True,editable=False)
    last_verified = django_models.DateTimeField(null=True,editable=False)
    created = django_models.DateTimeField(null=False,editable=False)

    class Meta:
        verbose_name_plural = "{}User TOTPs".format(" " * 8)

class TrafficControl(CacheableMixin,DbObjectMixin,django_models.Model):
    _buckets = None
    _bucketslen = None
    _buckets_currentid = None
    _buckets_currenttime = None
    _buckets_begintime = None
    _buckets_fetchtime = None

    _editable_columns = ("est_processtime","concurrency","iplimit","iplimitperiod","userlimit","userlimitperiod","enabled","active","buckettime","buckets")
    name = django_models.SlugField(max_length=128,null=False,editable=True,unique=True)
    enabled = django_models.BooleanField(default=True,editable=True,help_text="Enable/disable the traffic control")
    active = django_models.BooleanField(default=False,editable=False)
    est_processtime = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The estimated processing time(milliseconds) used to calculate the concurrency requests") #millisecond
    buckettime = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="Declare the time period(milliseconds) of the bucket, the est_processtime and the total milliseconds of one day should be divided by this value.") #milliseconds
    buckets = django_models.PositiveIntegerField(default=0,null=False,editable=False)
    concurrency = django_models.PositiveIntegerField(default=0,null=False,editable=True)
    iplimit = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The maximum requests per client ip which can be allowd in configure period")
    iplimitperiod = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The time period(seconds) configured for requests limit per client ip") #in seconds
    userlimit = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The maximum requests per user which can be allowd in configure period")
    userlimitperiod = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The time period(seconds) configured for requests limit per user") #in seconds
    modified = django_models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = django_models.DateTimeField(auto_now_add=timezone.now)

    class Meta:
        verbose_name_plural = "{}Traffic Control".format(" " * 9)

    class ExpiredBucketIds(object):
        def __init__(self,tcontrol,length):
            self.tcontrol = tcontrol
            self.length = length
            self.bucketid = None
        def __len__(self):
            return self.length
        def __iter__(self):
            self.bucketid = self.tcontrol._normalize_bucketid(self.tcontrol._buckets_currentid - self.length)
            return self

        def __next__(self):
            if self.bucketid == self.tcontrol._buckets_currentid:
                raise StopIteration()
            try:
                return self.bucketid
            finally:
                self.bucketid = self.tcontrol._normalize_bucketid(self.bucketid + 1)

    class Buckets(object):
        def __init__(self,tcontrol,expiredbuckets = 0):
            self.tcontrol = tcontrol
            if expiredbuckets == 0:
                self.expiredbuckets_beginindex = None
            else:
                self.expiredbuckets_beginindex = self.tcontrol._bucketslen - expiredbuckets - 1
            self.bucket = None
            self.index = None
            
        def __iter__(self):
            self.index = 0
            if self.expiredbuckets_beginindex is not None and self.expiredbuckets_beginindex == self.index:
                self.bucket = [self.tcontrol._buckets_begintime,self.tcontrol._normalize_bucketid(self.tcontrol._buckets_currentid - self.tcontrol._bucketslen + 1),"Expired"]
            else:
                self.bucket = [self.tcontrol._buckets_begintime,self.tcontrol._normalize_bucketid(self.tcontrol._buckets_currentid - self.tcontrol._bucketslen + 1),self.tcontrol._buckets[self.index]]
            return self

        def __next__(self):
            if self.index >= self.tcontrol._bucketslen:
                raise StopIteration()
            if self.bucket[1] == self.tcontrol._buckets_currentid:
                if self.bucket[0] != self.tcontrol._buckets_currenttime:
                    raise Exception("buckets_begintime({}) is incorrect.".format(self.tcontrol._buckets_begintime.strftime("%Y-%m-%d %H:%M:%S.%f"),self.tcontrol._buckets_currenttime.strftime("%Y-%m-%d %H:%M:%S.%f"),self.tcontrol._bucketslen))
            try:
                return self.bucket
            finally:
                self.index += 1
                if self.index < self.tcontrol._bucketslen:
                    if self.expiredbuckets_beginindex is not None and self.index >= self.expiredbuckets_beginindex and self.index < self.tcontrol._bucketslen - 1:
                        self.bucket = [self.bucket[0] + timedelta(milliseconds=self.tcontrol.buckettime),self.tcontrol._normalize_bucketid(self.bucket[1] + 1),"Expired"]
                    else:
                        self.bucket = [self.bucket[0] + timedelta(milliseconds=self.tcontrol.buckettime),self.tcontrol._normalize_bucketid(self.bucket[1] + 1),self.tcontrol._buckets[self.index]]

    @classmethod
    def get_model_change_cls(self):
        return TrafficControlChange

    def clean(self):
        super().clean()
        timediff = math.floor(settings.TRAFFICCONTROL_TIMEDIFF.microseconds / 1000)

        if self.userlimitperiod and 86400 % self.userlimitperiod != 0:
            raise ValidationError("The total seconds of a day(86400) should be divided by userlimitperiod.")
        
        if self.iplimitperiod and 86400 % self.iplimitperiod != 0:
            raise ValidationError("The total seconds of a day(86400) should be divided by iplimitperiod.")
        
        if self.est_processtime and self.est_processtime > 21600000:
            raise ValidationError("The estimate processtime can't be larger than 6 hours")

        if self.buckettime and self.est_processtime:
            if self.buckettime < timediff or self.est_processtime % self.buckettime != 0 or 86400000 % self.buckettime != 0:
                raise ValidationError("The buckettime should be larger than {}; Both the total milleseconds of one day(86400000) and estimated processing time({}) must be divided by the value of buckettime.".format(timediff,self.est_processtime))

            if int(self.est_processtime / self.buckettime) > settings.TRAFFICCONTROL_MAX_BUCKETS:
                raise ValidationError("The buckettime is too small, will slow the performance, it should be larger than {}".format( math.ceil(self.est_processtime / settings.TRAFFICCONTROL_MAX_BUCKETS)))

            totalbucketstime = self.est_processtime +  (50000 + self.est_processtime - 50000 % self.est_processtime)

            minbuckets = int(totalbucketstime / self.buckettime)

            while 86400000 % totalbucketstime != 0 and int((86400000 % totalbucketstime) / self.buckettime) < minbuckets:
                totalbucketstime += self.buckettime

            self.buckets = int(totalbucketstime / self.buckettime)
        else:
            self.buckets = 0
        self.active = True if (self.enabled and ((self.concurrency > 0 and self.est_processtime > 0 and self.buckettime) or (self.iplimit > 0 and self.iplimitperiod > 0) or (self.userlimit > 0 and self.userlimitperiod > 0))) else False

    def _normalize_bucketid(self,bucketid):
        if bucketid < 0:
            return bucketid + self.buckets
        elif bucketid < self.buckets:
            return bucketid
        else :
            return bucketid - self.buckets

    def get_buckets(self,today,milliseconds_in_day):
        """
        today: 
        milliseconds: milliseconds in today
        get the current bucket
        return (current bucketid,expired bucketids)
        """
        try:
            milliseconds = (milliseconds_in_day % self.totalbucketstime)
        except:
            self.totalbucketstime = self.buckets * self.buckettime
            milliseconds = (milliseconds_in_day % self.totalbucketstime)

        currentbucketid = math.floor(milliseconds / self.buckettime)
        currentbuckettime = today + timedelta(milliseconds=milliseconds_in_day - milliseconds % self.buckettime )

        if self._buckets_fetchtime is None:
            if self._buckets is None:
                self._buckets = [None] * int(self.est_processtime / self.buckettime)
                self._bucketslen = len(self._buckets)
            self._buckets_currenttime = currentbuckettime
            self._buckets_currentid = currentbucketid
            self._buckets_begintime = self._buckets_currenttime - timedelta(milliseconds=self.est_processtime - self.buckettime)
            #logger.warning("First time check,\n    Current bucket {} : {} , Expired Buckets: {}\n    Buckets:\n{}".format(self._buckets_currenttime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currentid,self._bucketslen - 1,"\n".join([ str((d[0].strftime("%Y-%m-%d %H:%M:%S.%f"),d[1],d[2])) for d in self.Buckets(self,self._bucketslen - 1)])))
            if self._bucketslen == 1:
                return [self._buckets_currentid,None]
            else:
                return [self._buckets_currentid,self.ExpiredBucketIds(self,self._bucketslen - 1)]
        elif self._buckets_currenttime != currentbuckettime:
            #a new bucket is required
            self._buckets.append(None)
            del self._buckets[0]
            self._buckets_currenttime = currentbuckettime
            self._buckets_currentid = currentbucketid
            #adjust the beginid and begintime
            self._buckets_begintime = self._buckets_begintime + timedelta(milliseconds=self.buckettime)

            buckets_begintime = self._buckets_currenttime - timedelta(milliseconds=self.est_processtime - self.buckettime)
            buckets = int(((self._buckets_currenttime - self._buckets_begintime).total_seconds()) * 1000 / self.buckettime)
            outdatedbuckets = buckets - self._bucketslen + 1
            self._buckets_begintime = buckets_begintime
            if outdatedbuckets >= self._bucketslen - 1:
                #all data is expired, fetch again.
                #logger.warning("New bucket time check, Fetch time {}\n    Current bucket {} : {} , Expired Buckets: {}\n    Buckets:\n{} ".format(self._buckets_fetchtime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currenttime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currentid,self._bucketslen - 1,"\n".join([ str((d[0].strftime("%Y-%m-%d %H:%M:%S.%f"),d[1],d[2])) for d in self.Buckets(self,self._bucketslen - 1)])))
                self._buckets_fetchtime = None
                return [self._buckets_currentid,self.ExpiredBucketIds(self,self._bucketslen - 1)]
            elif outdatedbuckets > 0:
                #part of the data is expired.
                #shift the not expired buckets
                for i in range(self._bucketslen - 1 - outdatedbuckets):
                    self._buckets[i] = self._buckets[i + outdatedbuckets]
            elif outdatedbuckets < 0:
                raise Exception("Incorrest status. buckets_begintime: {} , buckets_currenttime: {} , outdatedbuckets: {}".format(self._buckets_begintime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currenttime.strftime("%Y-%m-%d %H:%M:%S.%f"),outdatedbuckets))
        else:
            outdatedbuckets = None

        expired_bucketstime = (self._buckets_currenttime - (self._buckets_fetchtime - settings.TRAFFICCONTROL_TIMEDIFF)).total_seconds() * 1000
        if expired_bucketstime <= 0:
            #all previous buckets are up-to-date
            #logger.warning("{} bucket time check, Fetch time {}\n    Current bucket {} : {} , Expired Buckets: {}\n    Buckets:\n{}".format("Same" if outdatedbuckets is None else "New",self._buckets_fetchtime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currenttime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currentid,0,"\n".join([ str((d[0].strftime("%Y-%m-%d %H:%M:%S.%f"),d[1],d[2])) for d in self.Buckets(self)])))
            return [self._buckets_currentid,[]]
        else:
            expired_buckets = math.ceil(expired_bucketstime / self.buckettime)
            if expired_buckets >= self._bucketslen - 1:
                #all previous buckets are expired
                #logger.warning("{} bucket time check, Fetch time {}\n    Current bucket {} : {} , Expired Buckets: {}\n    Buckets:\n{}".format("Same" if outdatedbuckets is None else "New",self._buckets_fetchtime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currenttime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currentid,self._bucketslen - 1,"\n".join([ str((d[0].strftime("%Y-%m-%d %H:%M:%S.%f"),d[1],d[2])) for d in self.Buckets(self,self._bucketslen - 1)])))
                self._buckets_fetchtime = None
                return [self._buckets_currentid,self.ExpiredBucketIds(self,self._bucketslen - 1)]
            else:
                #logger.warning("{} bucket time check, Fetch time {}\n    Current bucket {} : {} , Expired Buckets: {}\n    Buckets:\n{}".format("Same" if outdatedbuckets is None else "New",self._buckets_fetchtime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currenttime.strftime("%Y-%m-%d %H:%M:%S.%f"),self._buckets_currentid,expired_buckets,"\n".join([ str((d[0].strftime("%Y-%m-%d %H:%M:%S.%f"),d[1],d[2])) for d in self.Buckets(self,expired_buckets)])))
                return [self._buckets_currentid,self.ExpiredBucketIds(self,expired_buckets)]

    def set_buckets(self,current_bucket_requests,fetchtime=None,expiredbuckets_requests=None):
        self._buckets[-1] = current_bucket_requests
        if fetchtime:
            self._buckets_fetchtime = fetchtime
            offset = self._bucketslen - 1 - len(expiredbuckets_requests)
            for i in range(len(expiredbuckets_requests)):
                self._buckets[i + offset] = int(expiredbuckets_requests[i]) if expiredbuckets_requests[i] else 0
        #logger.warning("Fetched the buckets requests, buckets: {} , fetch time:{} , running requests: {},\n    buckets:\n{}".format(self._bucketslen,self._buckets_fetchtime.strftime("%Y-%m-%d %H:%M:%S.%f"),self.runningrequests,"\n".join([ str((d[0].strftime("%Y-%m-%d %H:%M:%S.%f"),d[1],d[2])) for d in self.Buckets(self)])))
        

    @property
    def runningrequests(self):
        """
        should be called after set_current_buckets , expired_previous_buckets and set_previous_buckets 
        """
        if self._buckets is None:
            return 0

        result = 0
        for data in self._buckets:
            result += data

        return result
        

    @classmethod
    def refresh_cache(cls):
        """
        Popuate the data and save them to cache
        """
        logger.debug("Refresh TrafficControl cache")
        refreshtime = timezone.localtime()
        size = 0
        tcontrols = {}
        for obj in TrafficControlLocation.objects.select_related("tcontrol").all():
            size += 1
            if obj.tcontrol.active :
                tcontrols[(obj.domain,obj.location,obj.method)] = obj.tcontrol
                if settings.TRAFFICCONTROL_SUPPORTED:
                    tcontrols[obj.tcontrol.id] = obj.tcontrol
        cache.tcontrols = (tcontrols,size,refreshtime)
        return refreshtime

    

class TrafficControlLocation(DbObjectMixin,django_models.Model):
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4

    METHOD_CHOICES = (
        (GET,"GET"),
        (POST,"POST"),
        (PUT,"PUT"),
        (DELETE,"DELETE")
    )
    METHODS = {
        "GET":GET,
        "POST":POST,
        "PUT":PUT,
        "DELETE":DELETE
    }

    _editable_columns = ("domain","method","location")
    tcontrol = django_models.ForeignKey(TrafficControl, on_delete=django_models.CASCADE,editable=False,null=False)
    domain = django_models.CharField(max_length=128,null=False,editable=True)
    method = django_models.PositiveSmallIntegerField(choices=METHOD_CHOICES,null=False,editable=True)
    location = django_models.CharField(max_length=256,null=False,editable=True)
    modified = django_models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = django_models.DateTimeField(auto_now_add=timezone.now)

    class Meta:
        verbose_name_plural = "{}Traffic Control Locations"
        unique_together = [["domain","method","location"]]


class UserListener(object):
    @staticmethod
    @receiver(pre_save, sender=User)
    def pre_save_user(sender,instance,**kwargs):
        if not instance.id:
            instance.email = instance.email.strip().lower() if instance.email else None
            if not instance.email:
                instance.email = None

    @staticmethod
    @receiver(post_save, sender=User)
    def post_save_user(sender,instance,created,**kwargs):
        if not created:
            usercache = get_usercache(instance.id)
            if usercache and usercache.get(settings.GET_USER_KEY(instance.id)):
                usercache.set(settings.GET_USER_KEY(instance.id),instance,settings.STAFF_CACHE_TIMEOUT if instance.is_staff else settings.USER_CACHE_TIMEOUT)
                logger.debug("Cache the latest data of the user({1}<{0}>) to usercache".format(instance.id,instance.email))

    @staticmethod
    @receiver(post_delete, sender=User)
    def post_delete_user(sender,instance,**kwargs):
        usercache = get_usercache(instance.id)
        if usercache:
            usercache.delete(settings.GET_USER_KEY(instance.id))

class UserTokenListener(object):
    @staticmethod
    @receiver(post_save, sender=UserToken)
    def post_save_usertoken(sender,instance,created,**kwargs):
        if not created:
            usercache = get_usercache(instance.user_id)
            if usercache and usercache.get(settings.GET_USERTOKEN_KEY(instance.user_id)):
                #Only cache the user token only if it is already cached
                usercache.set(settings.GET_USERTOKEN_KEY(instance.user_id),instance,settings.STAFF_CACHE_TIMEOUT if instance.user.is_staff else settings.USER_CACHE_TIMEOUT)
                logger.debug("Cache the latest data of the user token({0}) to usercache".format(instance.user_id))

    @staticmethod
    @receiver(post_delete, sender=UserToken)
    def post_delete_usertoken(sender,instance,**kwargs):
        usercache = get_usercache(instance.user_id)
        if usercache:
            #delete the deleted user token from cache
            usercache.delete(settings.GET_USERTOKEN_KEY(instance.user_id))

class UserGroupListener(object):
    @receiver(pre_delete, sender=UserGroup)
    def pre_delete_group(sender,instance,**kwargs):
        if instance.is_public_group:
            raise Exception("Can't delete the public user group")

    @staticmethod
    @receiver(pre_save, sender=UserGroup)
    def check_public_group(sender,instance,**kwargs):
        if instance.id is None and instance.public_group() and instance.users == ["*"] and instance.excluded_users is None:
            raise Exception("Public user group already exists")

if defaultcache:
    class ModelChange(object):
        model = None
        key = None
        @classmethod
        def change(cls,timeout=None):
            try:
                defaultcache.set(cls.key,timezone.localtime(),timeout=timeout)
            except Exception as ex:
                DebugLog.warning(DebugLog.ERROR,None,None,None,None,"Failed to set the latest change time of the model '{}' to cache.{}".format(cls.__name__,traceback.format_exc(ex)))

        @classmethod
        def get_cachetime(cls):
            return None

        @classmethod
        def get_cachesize(cls):
            return None

        @classmethod
        def get_next_refreshtime(cls):
            return None

        @classmethod
        def status(cls):
            try:
                last_refreshed = cls.get_cachetime()
                cls.last_synced = defaultcache.get(cls.key)
                if not cls.last_synced:
                    if last_refreshed:
                        return (UP_TO_DATE,last_refreshed)
                    else:
                        return (OUTDATED,last_refreshed)


                count =  cls.model.objects.all().count()
                if count != cls.get_cachesize():
                    #cache is outdated
                    if cls.last_synced > last_refreshed:
                        return (OUTDATED,last_refreshed)
                    else:
                        return (OUT_OF_SYNC,last_refreshed)
    
                if count == 0:
                    return (UP_TO_DATE,last_refreshed)
    
                o = cls.model.objects.all().order_by("-modified").first()
                if o:
                    if last_refreshed and last_refreshed >= o.modified:
                        return (UP_TO_DATE,last_refreshed)
                    elif o.modified > cls.last_synced:
                        return (OUT_OF_SYNC,last_refreshed)
                else:
                    return (UP_TO_DATE,last_refreshed)
    
                if not last_refreshed:
                    return (OUTDATED,last_refreshed)
                elif cls.last_synced > last_refreshed:
                    return (OUTDATED,last_refreshed)
                else:
                    return (UP_TO_DATE,last_refreshed)
            except:
                #Failed, assume it is up to date
                DebugLog.warning(DebugLog.ERROR,None,None,None,None,"Failed to get the status of the model '{}' from cache.{}".format(cls.__name__,traceback.format_exc()))
                return (UP_TO_DATE,last_refreshed)

        @classmethod
        def is_changed(cls):
            try:
                last_modified = defaultcache.get(cls.key)
                if not last_modified:
                    #logger.debug("{} is not changed, no need to refresh cache data".format(cls.__name__[:-6]))
                    return False
                elif not cls.get_cachetime():
                    logger.debug("{} was changed, need to refresh cache data".format(cls.__name__[:-6]))
                    return True
                elif last_modified > cls.get_cachetime():
                    logger.debug("{} was changed, need to refresh cache data".format(cls.__name__[:-6]))
                    return True
                else:
                    #logger.debug("{} is not changed, no need to refresh cache data".format(cls.__name__[:-6]))
                    return False
            except :
                #Failed, assume it is not changed
                DebugLog.warning(DebugLog.ERROR,None,None,None,None,"Failed to check whether the model '{}' is changed or not.{}".format(cls.__name__,traceback.format_exc()))
                return False


    class TrafficControlChange(ModelChange):
        key = "tcontrol_last_modified"
        model = TrafficControlLocation

        @classmethod
        def get_cachetime(cls):
            return cache._tcontrols_ts

        @classmethod
        def get_cachesize(cls):
            return cache._tcontrolss_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._tcontrol_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            cache.refresh_tcontrol_cache()

        @staticmethod
        @receiver(post_save, sender=TrafficControl)
        def post_save_tcontrol(sender,*args,**kwargs):
            TrafficControlChange.change()

        @staticmethod
        @receiver(post_delete, sender=TrafficControl)
        def post_delete_tcontrol(sender,*args,**kwargs):
            TrafficControlChange.change()

        @staticmethod
        @receiver(post_save, sender=TrafficControlLocation)
        def post_save_location(sender,*args,**kwargs):
            TrafficControlChange.change()

        @staticmethod
        @receiver(post_delete, sender=TrafficControlLocation)
        def post_delete_location(sender,*args,**kwargs):
            TrafficControlChange.change()

        @classmethod
        def status(cls):
            status = super().status()
            if status[0] != UP_TO_DATE:
                return status

            try:
                last_refreshed = cls.get_cachetime()
                o = TrafficControl.objects.all().order_by("-modified").first()
                if o:
                    if last_refreshed and last_refreshed >= o.modified:
                        return (UP_TO_DATE,last_refreshed)
                    elif o.modified > cls.last_synced:
                        return (OUT_OF_SYNC,last_refreshed)
                else:
                    return (UP_TO_DATE,last_refreshed)
    
                return (UP_TO_DATE,last_refreshed)
            except:
                #Failed, assume it is up to date
                DebugLog.warning(DebugLog.ERROR,None,None,None,None,"Failed to get the status of the model 'TrafficControl' from cache.{}".format(traceback.format_exc()))
                return (UP_TO_DATE,last_refreshed)

    class IdentityProviderChange(ModelChange):
        key = "idp_last_modified"
        model = IdentityProvider

        @classmethod
        def get_cachetime(cls):
            return cache._idps_ts

        @classmethod
        def get_cachesize(cls):
            return cache._idps_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._idp_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            cache.refresh_idp_cache()

        @staticmethod
        @receiver(post_save, sender=IdentityProvider)
        def post_save_model(sender,*args,**kwargs):
            IdentityProviderChange.change()

        @staticmethod
        @receiver(post_delete, sender=IdentityProvider)
        def post_delete_model(sender,*args,**kwargs):
            IdentityProviderChange.change()

    class CustomizableUserflowChange(ModelChange):
        key = "customizableuserflow_last_modified"
        model = CustomizableUserflow

        @classmethod
        def get_cachetime(cls):
            return cache._userflows_ts

        @classmethod
        def get_cachesize(cls):
            return cache._userflows_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._userflow_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            cache.refresh_userflow_cache()

        @staticmethod
        @receiver(post_save, sender=CustomizableUserflow)
        def post_save_model(sender,*args,**kwargs):
            CustomizableUserflowChange.change()

        @staticmethod
        @receiver(post_delete, sender=CustomizableUserflow)
        def post_delete_model(sender,*args,**kwargs):
            CustomizableUserflowChange.change()

    class UserGroupChange(ModelChange):
        key = "usergroup_last_modified"
        model = UserGroup

        @classmethod
        def get_cachetime(cls):
            return cache._usergrouptree_ts

        @classmethod
        def get_cachesize(cls):
            return cache._usergrouptree_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._authorization_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            next_refreshtime = cls.get_next_refreshtime()
            if not next_refreshtime or  timezone.localtime() >= next_refreshtime:
                cache.refresh_usergroups()

        @staticmethod
        @receiver(post_save, sender=UserGroup)
        def post_save_model(sender,*args,**kwargs):
            UserGroupChange.change()

        @staticmethod
        @receiver(post_delete, sender=UserGroup)
        def post_delete_model(sender,*args,**kwargs):
            UserGroupChange.change()

    class UserAuthorizationChange(ModelChange):
        key = "userauthorization_last_modified"
        model = UserAuthorization

        @classmethod
        def get_cachetime(cls):
            return cache._userauthorization_ts

        @classmethod
        def get_cachesize(cls):
            return cache._userauthorization_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._authorization_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            next_refreshtime = cls.get_next_refreshtime()
            if not next_refreshtime or  timezone.localtime() >= next_refreshtime:
                cache.refresh_userauthorization()

        @staticmethod
        @receiver(post_save, sender=UserAuthorization)
        def post_save_model(sender,*args,**kwargs):
            UserAuthorizationChange.change()

        @staticmethod
        @receiver(post_delete, sender=UserAuthorization)
        def post_delete_model(sender,*args,**kwargs):
            UserAuthorizationChange.change()

    class UserGroupAuthorizationChange(ModelChange):
        key = "usergroupauthorization_last_modified"
        model = UserGroupAuthorization

        @classmethod
        def get_cachetime(cls):
            return cache._usergroupauthorization_ts

        @classmethod
        def get_cachesize(cls):
            return cache._usergroupauthorization_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._authorization_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            next_refreshtime = cls.get_next_refreshtime()
            if not next_refreshtime or  timezone.localtime() >= next_refreshtime:
                cache.refresh_usergroupauthorization()

        @staticmethod
        @receiver(post_save, sender=UserGroupAuthorization)
        def post_save_model(sender,*args,**kwargs):
            UserGroupAuthorizationChange.change()

        @staticmethod
        @receiver(post_delete, sender=UserGroupAuthorization)
        def post_delete_model(sender,*args,**kwargs):
            UserGroupAuthorizationChange.change()

else:
    class ModelChange(object):
        model = None

        @classmethod
        def get_cachetime(cls):
            return None

        @classmethod
        def get_cachesize(cls):
            return None

        @classmethod
        def status(cls):
            last_refreshed = cls.get_cachetime()
            count =  cls.model.objects.all().count()
            if count != cls.get_cachesize():
                return (OUTDATED,last_refreshed)

            if count == 0:
                return (UP_TO_DATE,last_refreshed)

            o = cls.model.objects.all().order_by("-modified").first()
            if o:
                if o.modified > last_refreshed:
                    return (OUTDATED,last_refreshed)
                else:
                    return (UP_TO_DATE,last_refreshed)
            else:
                return (UP_TO_DATE,last_refreshed)

        @classmethod
        def is_changed(cls):
            if (
                cls.model.objects.filter(modified__gt=cls.get_cachetime()).exists() or
                cls.model.objects.all().count() != cls.get_cachesize()
            ):
                logger.debug("{} was changed, need to refresh cache data".format(cls.__name__[:-6]))
                return True
            else:
                #logger.debug("{} is not changed, no need to refresh cache data".format(cls.__name__[:-6]))
                return False

    class TrafficControlChange(ModelChange):
        model = TrafficControlLocation

        @classmethod
        def get_cachetime(cls):
            return cache._tcontrols_ts

        @classmethod
        def get_cachesize(cls):
            return cache._tcontrols_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._tcontrol_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            cache.refresh_tcontrol_cache()

        @classmethod
        def status(cls):
            status = super().status()
            if status[0] != UP_TO_DATE:
                return status

            try:
                last_refreshed = cls.get_cachetime()
                o = TrafficControl.objects.all().order_by("-modified").first()
                if o:
                    if last_refreshed and last_refreshed >= o.modified:
                        return (UP_TO_DATE,last_refreshed)
                    elif o.modified > cls.last_synced:
                        return (OUT_OF_SYNC,last_refreshed)
                else:
                    return (UP_TO_DATE,last_refreshed)
    
                return (UP_TO_DATE,last_refreshed)
            except:
                #Failed, assume it is up to date
                DebugLog.warning(DebugLog.ERROR,None,None,None,None,"Failed to get the status of the model 'TrafficControl' from cache.{}".format(traceback.format_exc()))
                return (UP_TO_DATE,last_refreshed)
    class IdentityProviderChange(ModelChange):
        model = IdentityProvider

        @classmethod
        def get_cachetime(cls):
            return cache._idps_ts

        @classmethod
        def get_cachesize(cls):
            return cache._idps_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._idp_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            cache.refresh_idp_cache()


    class CustomizagbleUserflowChange(ModelChange):
        model = CustomizableUserflow

        @classmethod
        def get_cachetime(cls):
            return cache._userflows_ts

        @classmethod
        def get_cachesize(cls):
            return cache._userflows_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._userflow_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            cache.refresh_userflow_cache()

    class UserGroupChange(ModelChange):
        model = UserGroup

        @classmethod
        def get_cachetime(cls):
            return cache._usergrouptree_ts

        @classmethod
        def get_cachesize(cls):
            return cache._usergrouptree_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._authorization_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            next_refreshtime = cls.get_next_refreshtime()
            if not next_refreshtime or  timezone.localtime() >= next_refreshtime:
                cache.refresh_usergroups()

    class UserAuthorizationChange(ModelChange):
        model = UserAuthorization

        @classmethod
        def get_cachetime(cls):
            return cache._userauthorization_ts

        @classmethod
        def get_cachesize(cls):
            return cache._userauthorization_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._authorization_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            next_refreshtime = cls.get_next_refreshtime()
            if not next_refreshtime or  timezone.localtime() >= next_refreshtime:
                cache.refresh_userauthorization()

    class UserGroupAuthorizationChange(ModelChange):
        model = UserGroupAuthorization

        @classmethod
        def get_cachetime(cls):
            return cache._usergroupauthorization_ts

        @classmethod
        def get_cachesize(cls):
            return cache._usergroupauthorization_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._authorization_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            next_refreshtime = cls.get_next_refreshtime()
            if not next_refreshtime or  timezone.localtime() >= next_refreshtime:
                cache.refresh_usergroupauthorization()


@receiver(signals.global_warning,sender=object)
def secretkey_expireat_warning(sender,request,**kwargs):
    if not cache.idps :
        return
    now = timezone.localtime()
    for k,o in cache.idps.items() :
        if not isinstance(k,int):
            continue
        if not o.secretkey_expireat:
            continue
        if o.secretkey_expireat <= now:
            messages.error(request, 'The secret key used by identity provider "{}" has been expired  at "{}"'.format(o.name or o.idp,utils.format_datetime(o.secretkey_expireat)))
        elif o.secretkey_expireat - now < settings.SECRETKEY_EXPIREDAYS_WARNING:
            messages.warning(request, 'The secret key used by identity provider "{}" will be expired  at "{}"'.format(o.name or o.idp,utils.format_datetime(o.secretkey_expireat)))


