import re
import logging
import random
from datetime import datetime, timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import models, transaction
from django.contrib.postgres.fields import ArrayField
from django.db.models.signals import pre_delete, pre_save, post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import AbstractUser

import hashlib

from .cache import cache
from .utils import get_defaultcache, get_usercache

logger = logging.getLogger(__name__)

defaultcache = get_defaultcache()
usercache = get_usercache()

help_text_users = """
List all possible user emails in this group separated by new line character.
The following lists all valid options in the checking order
    1. All emails    : *
    2. Domain emails : starts with '@', followed by email domain. For example@dbca.wa.gov.au
    3. Email pattern : '*' represents any strings. For example test_*@dbca.wa.gov.au
    4. User email    : represent a single user email, For example test_user01@dbca.wa.gov.au
"""

help_text_domain = """
A domain or domain pattern
The following lists all valid options in the checking order
    1. Single Domain : Represent a single domain. For example oim.dbca.wa.gov.au.
    2. Regex Domain  : '*" represents any strings. For example  pbs*dbca.wa.gov.au
    3. Suffix Domain : Starts with '.' followed by a domain. For example .dbca.wa.gov.au
    4. All Domain    : '*'
"""

help_text_paths = """
List all possible paths separated by new line character.
The following lists all valid options in the checking order
    1. All path      : *
    2. Prefix path   : the paths except All path, regex path and exact path. For example /admin
    3. Regex path    : A regex string starts with '^'. For example ^.*/add$
    4. Exact path  : Starts with '=', represents a single request path . For example =/register
"""

sortkey_c = models.Func('sortkey',function='C',template='(%(expressions)s) COLLATE "%(function)s"')

class _ArrayField(ArrayField):
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
    all_domain_re = re.compile("^\*+$")
    sufix_re = re.compile("^\**\.(?P<sufix>([a-zA-Z0-9_\-]+)(\.[a-zA-Z0-9_\-]+)*)$")
    exact_re = re.compile("^([a-zA-Z0-9_\-]+)(\.[a-zA-Z0-9_\-]+)+$")
    #two digit values(10 - 99), high value has low priority
    base_sort_key = 99

    #match all domains if True.
    match_all = False
    def __init__(self,config):
        #the configuration of this request domain
        self.config = config
        #the sort key to sort all configured request domain, the front configuration has high priority than the later configuration
        self.sort_key = self.get_sort_key(config)

    def get_sort_key(self,config):
        return "{}:{}".format(self.base_sort_key,config)

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
            self._re = re.compile("^{}$".format(domain.replace(".","\.").replace("*","[a-zA-Z0-9\._\-]*")))
        except Exception as ex:
            raise ValidationError("The regex domain config({}) is invalid.{}".format(domain,str(ex)))

    def get_sort_key(self,config):
        return "{}:{}".format(self.base_sort_key,config.replace("*","~"))

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


class IdentityProvider(CacheableMixin,DbObjectMixin,models.Model):
    """
    The identity provider to authenticate user.
    IdentityProvider 'local' means local account
    IdentityProvider 'local_passwordless' means autenticating user without password
    """
    MANUALLY_LOGOUT = 1
    AUTO_LOGOUT = 2
    AUTO_LOGOUT_WITH_POPUP_WINDOW = 3

    LOGOUT_METHODS = (
        (MANUALLY_LOGOUT,"Manually Logout"),
        (AUTO_LOGOUT,"Auto Logout"),
        (AUTO_LOGOUT_WITH_POPUP_WINDOW,"Auto Logout With Popup Window")
    )


    LOCAL_PROVIDER = 'local'

    _editable_columns = ("name","userflow","logout_url","logout_method")

    #meaningful name set in auth2, this name will be used in some other place, so change it only if necessary
    name = models.CharField(max_length=64,unique=True,null=True)
    #unique name returned from b2c
    idp = models.CharField(max_length=256,unique=True,null=False,editable=False)
    #the user flow id dedicated for this identity provider
    userflow = models.CharField(max_length=64,blank=True,null=True)
    #the logout url to logout the user from identity provider
    logout_url = models.CharField(max_length=512,blank=True,null=True)
    #the way to logout from idp
    logout_method = models.PositiveSmallIntegerField(choices=LOGOUT_METHODS,blank=True,null=True)
    modified = models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = models.DateTimeField(auto_now_add=timezone.now)

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
        modified = None
        refreshtime = timezone.now()
        size = 0
        idps = {}
        for obj in cls.objects.all():
            size += 1
            idps[obj.idp] = obj
            if not modified:
                modified = obj.modified
            elif modified < obj.modified:
                modified = obj.modified
        cache.idps = (idps,size,refreshtime)

    @classmethod
    def get_idp(cls,idpid):
        """
        Return idp from cache
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

    def __str__(self):
        return self.name or self.idp

    class Meta:
        verbose_name_plural = " Identity Providers"

class CustomizableUserflow(CacheableMixin,DbObjectMixin,models.Model):
    """
    Customize userflow for domain.
    The domain '*' is the default settings.
    """
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

    default_verify_email_body="""<html lang="en-gb" >
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

    _editable_columns = ("default","mfa_set","mfa_reset","email","profile_edit","password_reset","page_layout","fixed","extracss","verifyemail_from","verifyemail_subject","verifyemail_body","sortkey")

    domain = models.CharField(max_length=128,null=False,help_text=help_text_domain)
    fixed = models.CharField(max_length=64,null=True,blank=True,help_text="The only user flow used by this domain if configured")
    default = models.CharField(max_length=64,null=True,blank=True,help_text="The default user flow used by this domain")
    mfa_set = models.CharField(max_length=64,null=True,blank=True,help_text="The mfa set user flow")
    mfa_reset = models.CharField(max_length=64,null=True,blank=True,help_text="The mfa reset user flow")
    #is not used in current logic
    email = models.CharField(max_length=64,null=True,blank=True,help_text="The email signup and signin user flow")
    profile_edit = models.CharField(max_length=64,null=True,blank=True,help_text="The user profile edit user flow")
    password_reset = models.CharField(max_length=64,null=True,blank=True,help_text="The user password reset user flow")

    extracss = models.TextField(null=True,blank=True)
    page_layout = models.TextField(null=True,blank=True)

    verifyemail_from = models.EmailField(null=True,blank=True)
    verifyemail_subject = models.CharField(max_length=512,null=True,blank=True)
    verifyemail_body = models.TextField(null=True,blank=True)

    sortkey = models.CharField(max_length=128,editable=False)

    modified = models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = models.DateTimeField(auto_now_add=timezone.now)

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
        self.sortkey = request_domain.sort_key

        if self.domain == "*":
            #default userflow
            if not self.page_layout:
                #set the page layout to default page layout if it is empty
                self.page_layout = self.default_layout
            if not self.verifyemail_body:
                #set the verify email body to the default body if it is emtpy
                self.verifyemail_body = self.default_verify_email_body

            #check the required fields
            invalid_columns = []
            for name in ("default","mfa_set","mfa_reset","profile_edit","password_reset","page_layout","verifyemail_from","verifyemail_subject","verifyemail_body"):
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
    def refresh_cache(cls):
        """
        Populate the cached data and save them to cache
        """
        logger.debug("Refresh Customizable Userflow cache")
        userflows = []
        defaultuserflow = None
        last_modified = None
        refreshtime = timezone.now()
        size = 0
        for o in cls.objects.all().order_by(sortkey_c.asc()):
            if o.is_default:
                defaultuserflow = o

            userflows.append(o)

            if not last_modified:
                last_modified = o.modified
            elif last_modified < o.modified:
                last_modified = o.modified

            size += 1

        if not defaultuserflow :
            raise Exception("The default customizable userflow configuration is missing.")
        elif not defaultuserflow.page_layout:
            defaultuserflow.page_layout = cls.default_layout

        for o in userflows:
            if o != defaultuserflow:
                o.defaultuserflow = defaultuserflow
                for name in ("fixed","default","mfa_set","mfa_reset","email","profile_edit","password_reset"):
                    if not getattr(o,name):
                        setattr(o,name,getattr(defaultuserflow,name))

            else:
                o.defaultuserflow = None

        cache.userflows = (userflows,defaultuserflow,size,refreshtime)


class UserEmail(object):
    """
    User email configuration.
    """
    match_all = False
    def __init__(self,config):
        self.config = config
        self.sort_key = "{}:{}".format(self.base_sort_key,config)

    all_email_re = re.compile("^\*+(@\*+)?$")
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
        elif "*" in email:
            return RegexUserEmail(email)
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
        return models.Q(email=self.config)

    def contain(self,useremail):
        return self.config == useremail.config

class DomainEmail(UserEmail):
    base_sort_key = 4

    def match(self,email):
        return email.endswith(self.config)

    @property
    def qs_filter(self):
        return models.Q(email__endswith=self.config)

    def contain(self,useremail):
        if isinstance(useremail,AllUserEmail):
            return False
        elif isinstance(useremail,ExactUserEmail):
            return self.match(useremail.config)
        elif isinstance(useremail,DomainEmail):
            return self.config == useremail.config
        else:
            return useremail.config.endswith(self.config)

class RegexUserEmail(UserEmail):
    base_sort_key = 6
    def __init__(self,email):
        super().__init__(email)
        try:
            self._qs_re = r"^{}$".format(email.replace(".","\.").replace('*','[a-zA-Z0-9\._\-\+]*'))
            self._re = re.compile(self._qs_re)
        except Exception as ex:
            raise ValidationError("The regex email config({}) is invalid.{}".format(email,str(ex)))

    def match(self,email):
        return True if self._re.search(email) else False

    @property
    def qs_filter(self):
        return models.Q(email__regex=self._qs_re)

    def contain(self,useremail):
        if isinstance(useremail,AllUserEmail):
            return False
        elif isinstance(useremail,ExactUserEmail):
            return self.match(useremail.config)
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

class UserGroup(CacheableMixin,DbObjectMixin,models.Model):
    _useremails = None
    _excluded_useremails = None

    _editable_columns = ("users","parent_group","excluded_users","identity_provider","groupid")

    name = models.CharField(max_length=32,unique=True,null=False)
    groupid = models.SlugField(max_length=32,null=False)
    parent_group = models.ForeignKey('self', on_delete=models.SET_NULL,null=True,blank=True)
    users = _ArrayField(models.CharField(max_length=64,null=False),help_text=help_text_users)
    excluded_users = _ArrayField(models.CharField(max_length=64,null=False),null=True,blank=True,help_text=help_text_users)
    identity_provider = models.ForeignKey(IdentityProvider, on_delete=models.SET_NULL,null=True,blank=True)
    modified = models.DateTimeField(editable=False,db_index=True)
    created = models.DateTimeField(auto_now_add=timezone.now)

    @classmethod
    def get_model_change_cls(self):
        return UserGroupChange

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
            self.modified = timezone.now()
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
                if useremail.contain(excluded_useremail):
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
                    if parent_useremail.contain(useremail):
                        contained = True
                        break
                if not contained:
                    raise ValidationError("The email pattern({}) in the current group({}) is not contained by the parent group({})".format(useremail.config,self,self.parent_group))
            #check whether excluded user email in parent group is not contained by this group
            for parent_excluded_useremail in self.parent_group.excluded_useremails:
                contained = False
                for useremail in self.useremails:
                    if useremail.contain(parent_excluded_useremail):
                        contained = True
                        break
                if not contained:
                    continue

                contained = False
                for excluded_useremail in self.excluded_useremails:
                    if excluded_useremail.contain(parent_excluded_useremail):
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
                        if useremail.contain(child_useremail):
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
                        if child_excluded_useremail.contain(excluded_useremail):
                            contained = True
                            break
                    if not contained:
                        raise ValidationError("The excluded email pattern({}) in the current group({}) is contained by the child group({})".format(excluded_useremail.config,self,child_group))

        #allow user in multible brother groups
        """
        #check between current group and its brother groups
        if self.parent_group:
            brother_groups = UserGroup.objects.filter(parent_group=self.parent_group)
            if self.id:
                brother_groups = brother_groups.exclude(id=self.id)
            for brother_group in brother_groups:
                for brother_useremail in brother_group.useremails:
                    contained_type = None
                    checked_useremail = None
                    for useremail in self.useremails:
                        if useremail.contain(brother_useremail) :
                            contained_type = "contain_brother"
                            for excluded_useremail in self.excluded_useremails:
                                if excluded_useremail.contain(brother_useremail):
                                    contained_type = None
                                    break
                            if contained_type:
                                checked_useremail = useremail
                                break
                        elif brother_useremail.contain(useremail):
                            contained_type = "contained_by_brother"
                            for excluded_useremail in brother_group.excluded_useremails:
                                if excluded_useremail.contain(useremail):
                                    contained_type = None
                                    break
                            if contained_type:
                                checked_useremail = useremail
                                break
                    if contained_type == "contain_brother":
                        raise ValidationError("The email pattern({1}) in the group({0}) containes the email pattern({3}) in the brother group({2})".format(self,checked_useremail.config,brother_group,brother_useremail.config))
                    elif contained_type == "contained_by_brother":
                        raise ValidationError("The email pattern({3}) in the brother group({2}) containes the email pattern({1}) in the group({0})".format(self,checked_useremail.config,brother_group,brother_useremail.config))
        """


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

    def delete(self,*args,**kwargs):
        logger.debug("Try to delete the usergroup {}({})".format(self.__class__.__name__,self))
        with transaction.atomic():
            super().delete(*args,**kwargs)

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
        modified = None
        refreshtime = timezone.now()
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

            if not modified:
                modified = group.modified
            elif modified < group.modified:
                modified = group.modified
        if not public_group and group_trees:
            raise Exception("Missing user group 'Public User'")
        #build the tree
        for key,val in group_trees.items():
            group,subgroups = val
            if group.parent_group_id:
                group_trees[group.parent_group_id][1].append(val)
        group_trees = [v for v in group_trees.values() if not v[0].parent_group_id]
        cache.usergrouptree = (group_trees,groups,public_group,dbca_group,size,refreshtime)

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
        for useremail in self.useremails:
            if useremail.match(email):
                #email is included in the useremails
                matched = True
                break

        if matched:
            if self.excluded_useremails:
                for useremail in self.excluded_useremails:
                    if useremail.match(email):
                        #email is excluded in the excluded_useremails
                        matched = False
                        break
        return matched


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

    class Meta:
        unique_together = [["users","excluded_users"]]
        verbose_name_plural = "     User Groups"

class RequestPath(object):
    match_all = False

    def __init__(self,config):
        self.config = config
        self.sort_key = "{}:{}".format(self.base_sort_key,config)

    all_path_re = re.compile("^\*+$")
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


class AuthorizationMixin(DbObjectMixin,models.Model):

    _request_domain = None
    _excluded_request_paths = None
    _request_paths = None

    _allow_all = None
    _deny_all = None

    _editable_columns = ("domain","paths","excluded_paths")

    domain = models.CharField(max_length=128,null=False,help_text=help_text_domain)
    paths = _ArrayField(models.CharField(max_length=128,null=False),null=True,blank=True,help_text=help_text_paths)
    excluded_paths = _ArrayField(models.CharField(max_length=128,null=False),null=True,blank=True,help_text=help_text_paths)
    sortkey = models.CharField(max_length=128,editable=False)
    modified = models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = models.DateTimeField(auto_now_add=timezone.now)

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

        #can't find the matched object
        return matched_authorizations

    class Meta:
        abstract = True

def _can_access(email,domain,path):
    """
    Return True if the user(email) can access domain/path; otherwise return False
    """
    email = email.lower()
    domain = domain.lower()
    groupskey = cache.get_email_groupskey(email)
    if not groupskey:
        usergroups = UserGroup.find_groups(email)[0]
        if not usergroups:
            #Not in any user group. can't access
            return False

        groupskey = cache.get_email_groupskey(email)

    authorizations = cache.get_authorizations(groupskey,domain)
    if authorizations is None:
        authorizations = AuthorizationMixin.find_authorizations(email,domain)
        cache.set_authorizations(groupskey,domain,authorizations)
    if authorizations:
        return any(obj.allow(path) for obj in authorizations)
    else:
        return False

def _can_access_debug(email,domain,path):
    """
    Return True if the user(email) can access domain/path; otherwise return False
    """
    email = email.lower()
    domain = domain.lower()
    start = datetime.now()
    authorizations = None
    try:
        groupskey = cache.get_email_groupskey(email)
        if not groupskey:
            usergroups = UserGroup.find_groups(email)[0]
            if not usergroups:
                #Not in any user group. can't access
                return False

            groupskey = cache.get_email_groupskey(email)

        authorizations = cache.get_authorizations(groupskey,domain)
        if authorizations is None:
            authorizations = AuthorizationMixin.find_authorizations(email,domain)
            cache.set_authorizations(groupskey,domain,authorizations)
        if authorizations:
            return any(obj.allow(path) for obj in authorizations)
        else:
            return False
    finally:
        diff = datetime.now() - start
        if diff.seconds > 0 or diff.microseconds > settings.AUTH_CHECKING_THRESHOLD_TIME:
            logger.warning("spend {0} milliseconds to check the authroization.user={1}, http request=https://{2}{3}".format(round((diff.seconds * 1000000 + diff.microseconds)/1000),email,domain,path))
            pass
        else:
            logger.debug("spend {0} milliseconds to check the authroization.user={1}, http request=https://{2}{3}, authorization object=\r\n\t{4})".format(round((diff.seconds * 1000000 + diff.microseconds)/1000),email,domain,path,"\r\n\t".join("{}({},domain={},paths={},excluded_paths={})".format(authorization.__class__.__name__,authorization,authorization.domain,authorization.paths,authorization.excluded_paths) for authorization in authorizations) if authorizations else "None"))
            pass

can_access = _can_access if settings.RELEASE else _can_access_debug

class UserAuthorization(CacheableMixin,AuthorizationMixin):
    user = models.EmailField(max_length=64)

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
        modified = None
        refreshtime = timezone.now()
        for authorization in UserAuthorization.objects.all().order_by("user",sortkey_c.asc()):
            size += 1
            if not modified:
                modified = authorization.modified
            elif modified < authorization.modified:
                modified = authorization.modified

            if not previous_user:
                userauthorization[authorization.user] = [authorization]
                previous_user = authorization.user
            elif previous_user == authorization.user:
                userauthorization[authorization.user].append(authorization)
            else:
                userauthorization[authorization.user] = [authorization]
                previous_user = authorization.user

        cache.userauthorization = (userauthorization,size,refreshtime)

    @classmethod
    def get_authorizations(cls,useremail):
        return cache.userauthorization.get(useremail)

    def __str__(self):
        return self.user

    class Meta:
        unique_together = [["user","domain"]]
        verbose_name_plural = "    User Authorizations"

class UserGroupAuthorization(CacheableMixin,AuthorizationMixin):
    usergroup = models.ForeignKey(UserGroup, on_delete=models.CASCADE)

    @classmethod
    def get_model_change_cls(self):
        return UserGroupAuthorizationChange

    @classmethod
    def refresh_cache(cls):
        logger.debug("Refresh UserGroupAuthorization cache")
        usergroupauthorization = {}
        previous_usergroup = None
        size = 0
        modified = None
        refreshtime = timezone.now()
        for authorization in UserGroupAuthorization.objects.all().order_by("usergroup","sortkey"):
            size += 1
            if not modified:
                modified = authorization.modified
            elif modified < authorization.modified:
                modified = authorization.modified

            if not previous_usergroup:
                usergroupauthorization[authorization.usergroup] = [authorization]
                previous_usergroup = authorization.usergroup
            elif previous_usergroup == authorization.usergroup:
                usergroupauthorization[authorization.usergroup].append(authorization)
            else:
                usergroupauthorization[authorization.usergroup] = [authorization]
                previous_usergroup = authorization.usergroup

        cache.usergroupauthorization = (usergroupauthorization,size,refreshtime)

    @classmethod
    def get_authorizations(cls,usergroup):
        return cache.usergroupauthorization.get(usergroup)

    def __str__(self):
        return str(self.usergroup)

    class Meta:
        unique_together = [["usergroup","domain"]]
        verbose_name_plural = "   User Group Authorizations"

class User(AbstractUser):
    last_idp = models.ForeignKey(IdentityProvider, on_delete=models.SET_NULL,editable=False,null=True)
    systemuser = models.BooleanField(default=False,editable=False)
    modified = models.DateTimeField(auto_now=timezone.now)

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

    class Meta(AbstractUser.Meta):
        swappable = 'AUTH_USER_MODEL'
        db_table = "auth_user"
        verbose_name_plural = "        User"
        unique_together = [["email"]]

class UserToken(models.Model):
    DISABLED = -1
    NOT_CREATED = -2
    EXPIRED = -3
    GOOD = 1
    WARNING = 2

    RANDOM_CHARS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYA0123456789~!@#$%^&*()-_+=`{}[];':\",./<>?"
    RANDOM_CHARS_MAX_INDEX = len(RANDOM_CHARS) - 1

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,primary_key=True,related_name="token",editable=False)
    enabled = models.BooleanField(default=False,editable=False)
    token = models.CharField(max_length=128,null=True,editable=False)
    created = models.DateTimeField(null=True,editable=False)
    expired = models.DateField(null=True,editable=False)
    modified = models.DateTimeField(editable=False,db_index=True,auto_now=True)

    @classmethod
    def generate_user_secret(cls):
        return "".join(cls.RANDOM_CHARS[random.randint(0,cls.RANDOM_CHARS_MAX_INDEX)] for i in range(0,32))

    @property
    def is_expired(self):
        if not self.enabled or not self.token:
            return True
        elif self.expired:
            return timezone.localdate() > self.expired
        else:
            return False

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

    class Meta:
        verbose_name_plural = "       User Access Tokens"

class UserTOTP(models.Model):
    email = models.CharField(max_length=64,null=False,editable=False)
    idp = models.CharField(max_length=256,null=False,editable=False)
    secret_key = models.CharField(max_length=128,null=False,editable=False)
    timestep = models.PositiveSmallIntegerField(null=False,editable=False)
    prefix = models.CharField(max_length=64,null=False,editable=False)
    issuer = models.CharField(max_length=64,null=False,editable=False)
    name = models.CharField(max_length=128,null=False,editable=False)
    algorithm = models.CharField(max_length=32,null=False,editable=False)
    digits = models.PositiveSmallIntegerField(null=False,editable=False)
    last_verified_code = models.CharField(max_length=16,null=True,editable=False)
    last_verified = models.DateTimeField(null=True,editable=False)
    created = models.DateTimeField(null=False,editable=False)

    class Meta:
        unique_together = [["email","idp"]]

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
            if usercache.get(settings.GET_USER_KEY(instance.id)):
                usercache.set(settings.GET_USER_KEY(instance.id),instance,settings.USER_CACHE_TIMEOUT)
                logger.debug("Cache the latest data of the user({1}<{0}>) to usercache".format(instance.id,instance.email))

    @staticmethod
    @receiver(post_delete, sender=User)
    def post_delete_user(sender,instance,**kwargs):
        usercache.delete(settings.GET_USER_KEY(instance.id))

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
        key = None
        @classmethod
        def change(cls):
            defaultcache.set(cls.key,timezone.now())

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
        def is_changed(cls):
            last_modified = defaultcache.get(cls.key)
            if not last_modified:
                logger.debug("{} is not changed, no need to refresh cache data".format(cls.__name__[:-6]))
                return False
            elif not cls.get_cachetime():
                logger.debug("{} was changed, need to refresh cache data".format(cls.__name__[:-6]))
                return True
            elif last_modified > cls.get_cachetime():
                logger.debug("{} was changed, need to refresh cache data".format(cls.__name__[:-6]))
                return True
            else:
                logger.debug("{} is not changed, no need to refresh cache data".format(cls.__name__[:-6]))
                return False


    class IdentityProviderChange(ModelChange):
        key = "idp_last_modified"

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
        def post_save(sender,*args,**kwargs):
            IdentityProviderChange.change()

        @staticmethod
        @receiver(post_delete, sender=IdentityProvider)
        def post_delete(sender,*args,**kwargs):
            IdentityProviderChange.change()

    class CustomizableUserflowChange(ModelChange):
        key = "customizableuserflow_last_modified"

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
        def post_save(sender,*args,**kwargs):
            CustomizableUserflowChange.change()

        @staticmethod
        @receiver(post_delete, sender=CustomizableUserflow)
        def post_delete(sender,*args,**kwargs):
            CustomizableUserflowChange.change()

    class UserGroupChange(ModelChange):
        key = "usergroup_last_modified"

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
            if cache._authorization_cache_check_time.can_run():
                cache.refresh_usergroups()

        @staticmethod
        @receiver(post_save, sender=UserGroup)
        def post_save(sender,*args,**kwargs):
            UserGroupChange.change()

        @staticmethod
        @receiver(post_delete, sender=UserGroup)
        def post_delete(sender,*args,**kwargs):
            UserGroupChange.change()

    class UserAuthorizationChange(ModelChange):
        key = "userauthorization_last_modified"

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
            if cache._authorization_cache_check_time.can_run():
                cache.refresh_userauthorization()

        @staticmethod
        @receiver(post_save, sender=UserAuthorization)
        def post_save(sender,*args,**kwargs):
            UserAuthorizationChange.change()

        @staticmethod
        @receiver(post_delete, sender=UserAuthorization)
        def post_delete(sender,*args,**kwargs):
            UserAuthorizationChange.change()

    class UserGroupAuthorizationChange(ModelChange):
        key = "usergroupauthorization_last_modified"

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
            if cache._authorization_cache_check_time.can_run():
                cache.refresh_usergroupauthorization()

        @staticmethod
        @receiver(post_save, sender=UserGroupAuthorization)
        def post_save(sender,*args,**kwargs):
            UserGroupAuthorizationChange.change()

        @staticmethod
        @receiver(post_delete, sender=UserGroupAuthorization)
        def post_delete(sender,*args,**kwargs):
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
        def is_changed(cls):
            if (
                cls.model.objects.filter(modified__gt=cls.get_cachetime()).exists() or
                cls.model.objects.all().count() != cls.get_cachesize()
            ):
                logger.debug("{} was changed, need to refresh cache data".format(cls.__name__[:-6]))
                return True
            else:
                logger.debug("{} is not changed, no need to refresh cache data".format(cls.__name__[:-6]))
                return False

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
            cache.refresh_usergroupauthorization()
