import re
import logging
from datetime import datetime,timedelta

from django.conf import settings
from django.contrib.sessions.models import Session
from django.core import management
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import models,transaction
from django.contrib.postgres.fields import ArrayField
from django.db.models.signals import pre_delete,pre_save
from django.dispatch import receiver

from ipware.ip import get_client_ip
import hashlib

from .cache import cache

logger = logging.getLogger(__name__)

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
    1. Single Domain : Represent a single domain. For example oim.dbca.wa.gov.au. Only single domain can config path and excluded path
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

class _ArrayField(ArrayField):
    def clean(self, value, model_instance):
        return super().clean([v for v in value if v],model_instance)

class IdentityProvider(models.Model):
    name = models.SlugField(max_length=32,blank=True,unique=True,null=True)
    idp = models.CharField(max_length=256,unique=True,null=False,editable=False)
    userflow = models.CharField(max_length=64,blank=True,null=True)
    logout_url = models.CharField(max_length=512,blank=True,null=True)
    modified = models.DateTimeField(auto_now=timezone.now)
    created = models.DateTimeField(auto_now_add=timezone.now)

    @classmethod
    def get_userflow(cls,name,refresh=False):
        idps = cache.idps
        if refresh or not idps:
            logger.debug("Refresh idp cache")
            modified = None
            size = 0
            idps = {}
            for obj in cls.objects.all():
                size += 1
                idps[obj.name] = obj
                if not modified:
                    modified = obj.modified
                elif modified < obj.modified:
                    modified = obj.modified
            cache.idps = (idps,size,modified)
        idp = idps.get(name) if name else None
        if idp and idp.userflow:
            return idp.userflow
        else:
            return settings.SOCIAL_AUTH_AZUREAD_B2C_OAUTH2_POLICY

    def __str__(self):
        return self.name if self.name else self.idp

class UserToken(models.Model):
    DISABLED = -1
    NOT_CREATED = -2
    EXPIRED = -3
    GOOD = 1
    WARNING = 2

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,primary_key=True,related_name="token",editable=False)
    enabled = models.BooleanField(default=False,editable=False)
    token = models.CharField(max_length=128,null=True,editable=False)
    created = models.DateTimeField(null=True,editable=False)
    expired = models.DateField(null=True,editable=False)
    modified = models.DateTimeField(editable=False,db_index=True,auto_now=True)

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

    def generate_token(self):
        """
        generate an access token
        """
        self.created = timezone.localtime()
        if settings.USER_ACCESS_TOKEN_LIFETIME:
            self.expired = self.created.date() + settings.USER_ACCESS_TOKEN_LIFETIME
        else:
            self.expired = None
        self.token = hashlib.sha256('{}|{}|{}|{}|{}|{}|{}'.format(self.user.email,self.user.is_superuser,self.user.is_staff,self.user.is_active,self.created.timestamp(),self.expired.isoformat() if self.expired else "9999-12-31",settings.SECRET_KEY).lower().encode('utf-8')).hexdigest()


class UserEmail(object):
    match_all = False
    def __init__(self,config):
        self.config = config
        self.sort_key = "{}:{}".format(self.base_sort_key,config)

    all_email_re = re.compile("^\*+$")
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

class ExactUserEmail(UserEmail):
    base_sort_key = 8

    def match(self,email):
        return self.config == email

class DomainEmail(UserEmail):
    base_sort_key = 4

    def match(self,email):
        return email.endswith(self.config)

class RegexUserEmail(UserEmail):
    base_sort_key = 6
    def __init__(self,email):
        super().__init__(email)
        try:
            self._re = re.compile("^{}$".format(email.replace('*','[a-zA-Z0-9\._\-]*')))
        except Exception as ex:
            raise ValidationError("The regex email config({}) is invalid.{}".format(email,str(ex)))

    def match(self,email):
        return True if self._re.search(email) else False

class DbObjectMixin(object):
    _db_obj = None

    @property
    def db_obj(self):
        if not self.id:
            return None

        if not self._db_obj:
            self._db_obj = self.__class__.objects.get(id=self.id)
        return self._db_obj

class UserGroup(DbObjectMixin,models.Model):
    _useremails = None
    _excluded_useremails = None

    _usergroup_trees = None
    _changed = False
    _config_changed = False

    name = models.CharField(max_length=32,unique=True)
    parent_group = models.ForeignKey('self', on_delete=models.SET_NULL,null=True,blank=True)
    users = _ArrayField(models.CharField(max_length=64,null=False),help_text=help_text_users)
    excluded_users = _ArrayField(models.CharField(max_length=64,null=False),null=True,blank=True,help_text=help_text_users)
    identity_provider = models.ForeignKey(IdentityProvider, on_delete=models.SET_NULL,null=True,blank=True)
    modified = models.DateTimeField(editable=False,db_index=True)
    created = models.DateTimeField(auto_now_add=timezone.now)

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

        if self.id is None:
            self.modified = timezone.now()
        else:
            if self.users != self.db_obj.users or self.parent_group != self.db_obj.parent_group or self.excluded_users != self.db_obj.excluded_users or self.identity_provider != self.db_obj.identity_provider:
                self.modified = timezone.now()
                self._changed = True
                self._config_changed = True
            elif self.name != self.db_obj.name:
                self._changed = True

        if not self.parent_group and not self.is_public_group():
            self.parent_group = self.public_group()

    @classmethod
    def public_group(cls,auto_create=True):
        obj = cls.objects.filter(users=["*"],excluded_users__isnull=True).first()
        if not obj and auto_create:
            obj = UserGroup(name="Public User",users=["*"],excluded_users=None)
            obj.modified = timezone.now()
            obj.save()
        return obj

    def is_public_group(self):
        return self.users == ["*"] and self.excluded_users is None

    def save(self,*args,**kwargs):
        if self.id is not None and not self._changed:
            #nothing was changed
            return 
        logger.debug("Save the changed {}({})".format(self.__class__.__name__,self))
        with transaction.atomic():
            super().save(*args,**kwargs)

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
    def get_grouptree(cls,refresh=False):
        if refresh or not cache.usergrouptree:
            logger.debug("Populate UserGroup trees")
            group_trees = {}
            modified = None
            size = 0
            for group in cls.objects.all():
                size += 1
                group_trees[group.id] = (group,[])
                if not modified:
                    modified = group.modified
                elif modified < group.modified:
                    modified = group.modified
            #build the tree
            for key,val in group_trees.items():
                group,subgroups = val
                if group.parent_group:
                    group_trees[group.parent_group.id][1].append(val)
            group_trees = [v for v in group_trees.values() if not v[0].parent_group]
            cache.usergrouptree = (group_trees,size,modified)

        return cache.usergrouptree

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
    def find(cls,email):
        """
        email should be in lower case
        Return the matched user group; if not found, return None
        """
        trees = cls.get_grouptree()
        matched_group = None
        matched = False
        while trees:
            matched = False
            #try to find a matched group from the trees
            for group,subgroups in trees:
                matched = group.contain(email)
                if matched:
                    #user is included in this group, try to find the matched subgroup
                    matched_group = group
                    trees = subgroups
                    break

            if not matched:
                trees = None

        return matched_group

    @classmethod
    def get_identity_provider(cls,email):
        email = email.lower()
        cache.refresh_authorization_cache()
        group = cls.find(email)
        while group:
            if group.identity_provider:
                return group.identity_provider
            else:
                group = group.parent_group

        return None

    class Meta:
        unique_together = [["users","excluded_users"]]


class RequestDomain(object):
    all_domain_re = re.compile("^(\*|\.)+$")
    sufix_re = re.compile("^(\**\.)+(?P<sufix>([a-zA-Z0-9_\-]+)(\.[a-zA-Z0-9_\-]+)+)$")
    exact_re = re.compile("^([a-zA-Z0-9_\-]+)(\.[a-zA-Z0-9_\-]+)+$")

    def __init__(self,config):
        self.config = config
        self.sort_key = "{}:{}".format(self.base_sort_key,config)

    @classmethod
    def get_instance(cls,domain):
        domain = domain.strip() if domain else None
        if not domain:
            return None

        domain = domain.lower()
        for prefix in ("https://","http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
                break

        if cls.all_domain_re.search(domain):
            return AllRequestDomain()

        m = cls.sufix_re.search(domain)
        if m:
            return SufixRequestDomain(".{}".format(m.group("sufix")))

        elif cls.exact_re.search(domain):
            return ExactRequestDomain(domain)
        else:
            return RegexRequestDomain(domain)

    def match(self,domain):
        return False

class AllRequestDomain(RequestDomain):
    base_sort_key = 80

    def __init__(self):
        super().__init__("*")

    def match(self,email):
        return True

class ExactRequestDomain(RequestDomain):
    base_sort_key = 20

    def match(self,domain):
        return self.config == domain

class SufixRequestDomain(RequestDomain):
    base_sort_key = 60

    def match(self,domain):
        if not domain:
            return False
        return domain.endswith(self.config)

class RegexRequestDomain(RequestDomain):
    base_sort_key = 40
    def __init__(self,domain):
        super().__init__(domain)
        self.sort_key = "{}:{:0>3}-{}".format(self.base_sort_key,len(domain),domain)
        try:
            self._re = re.compile("^{}$".format(domain.replace("*","[a-zA-Z0-9\._\-]*")))
        except Exception as ex:
            raise ValidationError("The regex domain config({}) is invalid.{}".format(domain,str(ex)))

    def match(self,domain):
        if not domain:
            return False

        return True if self._re.search(domain) else False

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
    _changed = False
    _config_changed = False

    _request_domain = None
    _excluded_request_paths = None
    _request_paths = None

    _allow_all = None
    _deny_all = None

    domain = models.CharField(max_length=64,null=False,help_text=help_text_domain)
    paths = _ArrayField(models.CharField(max_length=128,null=False),null=True,blank=True,help_text=help_text_paths)
    excluded_paths = _ArrayField(models.CharField(max_length=128,null=False),null=True,blank=True,help_text=help_text_paths)
    sortkey = models.CharField(max_length=96,editable=False)
    modified = models.DateTimeField(editable=False,db_index=True)
    created = models.DateTimeField(auto_now_add=timezone.now)

    @property
    def allow_all(self):
        if self._allow_all is None:
            if (not self.request_paths or all(p.match_all for p in self.request_paths)) and not self.excluded_request_paths:
                self._allow_all = True
            else:
                self._allow_all = False

        return self._allow_all

    @property
    def deny_all(self):
        if self._deny_all is None:
            if self.allow_all:
                self._deny_all = False
            elif self.excluded_request_paths and all(p.match_all for p in self.excluded_request_paths):
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
        elif isinstance(request_domain,ExactRequestDomain) or all(p.match_all for p in request_paths):
            self.paths = [p.config for p in request_paths]
        else:
            raise ValidationError("A domain pattern only supports empty path or all path")

        excluded_request_paths = self.get_request_paths(self.excluded_paths)
        if not excluded_request_paths:
            self.excluded_paths = None
        elif isinstance(request_domain,ExactRequestDomain) or all(p.match_all for p in excluded_request_paths):
            self.excluded_paths = [p.config for p in excluded_request_paths]
        else:
            raise ValidationError("A domain pattern only supports empty excluded path or all excluded path")

        if self.id is None:
            self.modified = timezone.now()
        else:
            if self.db_obj.domain != self.domain or self.db_obj.excluded_paths != self.excluded_paths or self.db_obj.paths != self.paths:
                self.modified = timezone.now()
                self._changed = True
                self._config_changed = True


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

    def save(self,*args,**kwargs):
        if self.id is not None and not self._changed:
            #nothing was changed
            return 
        logger.debug("Save the changed {}({})".format(self.__class__.__name__,self))
        with transaction.atomic():
            super().save(*args,**kwargs)

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
    def find(email,domain):
        """
        email should be in lower case
        domain should be in lower case
        return matched UserAuthorization or UserGroupAuthorization;return None if can't found
        """
        #try to find the matched userauthorization
        userauthorization = UserAuthorization.get_authorization(email)
        if userauthorization:
            for requests in userauthorization:
                if requests.request_domain.match(domain):
                    return requests
        
        #try to find the matched usergroupauthorization 
        usergroup = UserGroup.find(email)
        while usergroup:
            grouprequests = UserGroupAuthorization.get_authorization(usergroup)
            if grouprequests:
                for requests in grouprequests:
                    if requests.request_domain.match(domain):
                        return requests
            usergroup = usergroup.parent_group

        #can't find the matched object
        return None

    class Meta:
        abstract = True

def _can_access(email,domain,path):
    """
    Return True if the user(email) can access domain/path; otherwise return False
    """
    email = email.lower()
    domain = domain.lower()
    requests = cache.get_authorization(email,domain)
    if not requests:
        requests = AuthorizationMixin.find(email,domain)
        if requests:
            cache.set_authorization(email,domain,requests)
    if requests:
        return requests.allow(path)
    else:
        return False

def _can_access_debug(email,domain,path):
    """
    Return True if the user(email) can access domain/path; otherwise return False
    """
    email = email.lower()
    domain = domain.lower()
    start = datetime.now()
    requests = None
    try:
        requests = cache.get_authorization(email,domain)
        if not requests:
            requests = AuthorizationMixin.find(email,domain)
            if requests:
                cache.set_authorization(email,domain,requests)
        if requests:
            return requests.allow(path)
        else:
            return False
    finally:
        diff = datetime.now() - start
        if diff.seconds > 0 or diff.microseconds > 3000:
            logger.warning("spend {0}.{1:0>6} seconds to check the authroization.user={2}, request=https://{3}{4}, requests={5})".format(diff.seconds,diff.microseconds,email,domain,path,"{}({},domain={},paths={},excluded_paths={})".format(requests.__class__.__name__,requests,requests.domain,requests.paths,requests.excluded_paths) if requests else "None"))
            pass
        else:
            logger.debug("spend {0}.{1:0>6} seconds to check the authroization.user={2}, request=https://{3}{4}, requests={5})".format(diff.seconds,diff.microseconds,email,domain,path,"{}({},domain={},paths={},excluded_paths={})".format(requests.__class__.__name__,requests,requests.domain,requests.paths,requests.excluded_paths) if requests else "None"))
            pass

can_access = _can_access_debug if settings.DEBUG else _can_access

class UserAuthorization(AuthorizationMixin):
    user = models.EmailField(max_length=64)

    def clean(self):
        super().clean()
        self.user = self.user.strip().lower() if self.user else None
        if not self.user:
            raise ValidationError("Useremail is empty")

    @classmethod
    def get_authorization(cls,useremail,refresh=False):
        if refresh or not cache.userauthorization:
            logger.debug("Populate UserAuthorization map")
            userauthorization = {}
            previous_user = None
            size = 0
            modified = None
            for authorization in UserAuthorization.objects.all().order_by("user","sortkey"):
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
            
            cache.userauthorization = (userauthorization,size,modified)

        return cache.userauthorization.get(useremail)

        

    def __str__(self):
        return self.user

    class Meta:
        unique_together = [["user","domain"]]

class UserGroupAuthorization(AuthorizationMixin):
    usergroup = models.ForeignKey(UserGroup, on_delete=models.CASCADE)

    @classmethod
    def get_authorization(cls,usergroup,refresh=False):
        if refresh or not cache.usergroupauthorization :
            logger.debug("Populate UserGroupAuthorization map")
            usergroupauthorization = {}
            previous_usergroup = None
            size = 0
            modified = None
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
            

            cache.usergroupauthorization = (usergroupauthorization,size,modified)

        return cache.usergroupauthorization.get(usergroup)

    def __str__(self):
        return str(self.usergroup)

    class Meta:
        unique_together = [["usergroup","domain"]]

class UserGroupListener(object):
    @staticmethod
    @receiver(pre_delete, sender=UserGroup)
    def delete_public_group(sender,instance,**kwargs):
        if instance.is_public_group():
            raise Exception("Can't delete the public user group")

    @staticmethod
    @receiver(pre_save, sender=UserGroup)
    def check_public_group(sender,instance,**kwargs):
        if instance.id is None and instance.is_public_group() and instance.public_group(False):
            raise Exception("Public user group already exists")

