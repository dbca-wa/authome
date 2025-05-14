import logging
import traceback
import json
from datetime import datetime, timedelta
from collections import OrderedDict

from django.conf import settings
from django.utils import timezone
from django.core.cache import caches
from django.urls import reverse

from .. import utils
from ..exceptions import InvalidDomainException


logger = logging.getLogger(__name__)

if settings.USER_CACHES == 0:
    get_usercache = lambda userid:None
elif settings.USER_CACHES == 1:
    get_usercache = lambda userid:caches[settings.USER_CACHE_ALIAS]
else:
    get_usercache = lambda userid:caches[settings.USER_CACHE_ALIAS(userid)]

if settings.CACHE_SERVER:
    get_defaultcache = lambda :caches['default']
else:
    get_defaultcache = lambda :None

defaultcache = get_defaultcache()

class TaskRunable(object):
    def can_run(self,dt=None):
        """
        Return True if the task can run;otherwise return False
        """
        return False


class IntervalTaskRunable(TaskRunable):
    """
    A interval based task runable class.
    Interval is the number of seconds between the task run
    A day can be divided by a valid interval.
    """
    def __init__(self,name,interval):
        self._name = name
        self._interval = interval
        self._next_runtime = None

    _seconds_4_nextrun = staticmethod(lambda seconds_in_day,interval: seconds_in_day + (interval - seconds_in_day % interval))
    def can_run(self,dt=None):
        if dt:
            dt = timezone.localtime(dt)
        else:
            dt = timezone.localtime()

        if not self._next_runtime:
            #not run before, don't run before the next scheduled runtime.
            today = datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo)
            self._next_runtime = today + timedelta(seconds = self._seconds_4_nextrun((dt - today).seconds,self._interval))
            #logger.debug("No need to run task({}), next runtime is {}".format(self._name,self._next_runtime.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        elif self._next_runtime > dt:
            #Don't run before the next scheduled runtime
            #logger.debug("No need to run task({}), next runtime is {}".format(self._name,self._next_runtime.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        else:
            #Run now, and set the next scheudled runtime.
            today = datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo)
            self._next_runtime = today + timedelta(seconds = self._seconds_4_nextrun((dt - today).seconds,self._interval))
            logger.debug("Run task({}) now, next runtime is {}".format(self._name,self._next_runtime.strftime("%Y-%m-%d %H:%M:%S")))
            return True

    @property
    def next_runtime(self):
        if not self._next_runtime:
            self.can_run()
        return self._next_runtime


class HourListTaskRunable(TaskRunable):
    """
    A hour list base task runable class
    The hour list is the list of hour(0-23) when the task should run

    """
    def __init__(self,name,hours):
        self._name = name
        self._next_runtime = None
        self._index = None
        self._hours = hours
        if len(self._hours) == 1:
            self._timediffs = [timedelta(hours=24)]
        else:
            self._timediffs = []

            i = 0
            while i < len(self._hours):
                if i == 0:
                    self._timediffs.append(timedelta(hours=24 - self._hours[-1] + self._hours[0]))
                else:
                    self._timediffs.append(timedelta(hours=self._hours[i] - self._hours[i-1]))
                i += 1

    def can_run(self,dt=None):
        if dt:
            dt = timezone.localtime(dt)
        else:
            dt = timezone.localtime()

        if not self._next_runtime:
            #not run before, don' run before the next scheduled time
            self._index = 0
            self._next_runtime = datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo) + timedelta(hours=self._hours[0])
            while self._next_runtime <= dt:
                if self._index == len(self._hours) - 1:
                    self._index = 0
                else:
                    self._index += 1
                self._next_runtime += self._timediffs[self._index]
            #logger.debug("No need to run task({}), next runtime is {}".format(self._name,self._next_runtime.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        elif self._next_runtime > dt:
            #don't run before the next sheduled time
            #logger.debug("No need to run task({}), next runtime is {}".format(self._name,self._next_runtime.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        else:
            #run and set the next scheduled time
            while self._next_runtime <= dt:
                if self._index == len(self._hours) - 1:
                    self._index = 0
                else:
                    self._index += 1
                self._next_runtime += self._timediffs[self._index]
            logger.debug("Run task({}) now, next runtime is {}".format(self._name,self._next_runtime.strftime("%Y-%m-%d %H:%M:%S")))
            return True

    @property
    def next_runtime(self):
        if not self._next_runtime:
            self.can_run()
        return self._next_runtime


class _BaseMemoryCache(object):
    """
    Local memory cache
    """
    def __init__(self):
        super().__init__()
        #model UserGroup cache
        self._usergrouptree = None
        self._usergroups = None
        self._dbca_group = None
        self._public_group = None
        self._usergrouptree_size = None
        self._usergrouptree_ts = None

        #model UserGroupAuthorization cache
        self._usergroupauthorization = None
        self._usergroupauthorization_size = None
        self._usergroupauthorization_ts = None

        #model CustomizableUserflow cache
        self._userflows = None
        self._userflows_map = {}
        self._defaultuserflow = None
        self._userflows_size = None
        self._userflows_ts = None

        #model IdentityProvider cache
        self._idps = None
        self._idps_size = None
        self._idps_ts = None

        #model TrafficControl cache
        self._tcontrols = None
        self._tcontrols_size = None
        self._tcontrols_ts = None

        #user authentication cache
        self._auth_map = OrderedDict() 
        self._staff_auth_map = OrderedDict() 
        #user basic authentication cache
        self._basic_auth_map = OrderedDict() 
        self._auth_cache_ts = None

        #the map between groups key and groups key
        #the purpose of this map is to use the same tuple instance of same groups keys
        self._groupskey_map = {}
        #the map between email and groups key
        self._email_groups_map = OrderedDict()
        #the map between public email and groups key
        self._public_email_groups_map = OrderedDict()
        #the map between groups key and groups
        self._groups_map = {}
        self._emailgroups_ts = None

        self._clientdomains = set()

        #the map between (groups,domain) and  authorization
        self._groups_authorization_map = OrderedDict() 
        self._groups_authorization_map_ts = None

        #The runable task to clean authenticaton map and basic authenticaton map
        self._auth_cache_clean_time = HourListTaskRunable("authentication cache",settings.AUTH_CACHE_CLEAN_HOURS)

        #The runable task to check UserGroup, UserAuthorization and UserGroupAuthorication cache
        self._authorization_cache_check_time = IntervalTaskRunable("authorization cache",settings.AUTHORIZATION_CACHE_CHECK_INTERVAL) if settings.AUTHORIZATION_CACHE_CHECK_INTERVAL > 0 else HourListTaskRunable("authorization cache",settings.AUTHORIZATION_CACHE_CHECK_HOURS)

        #The runable task to check CustomizableUserflow cache
        self._userflow_cache_check_time = IntervalTaskRunable("customizable userflow cache",settings.USERFLOW_CACHE_CHECK_INTERVAL) if settings.USERFLOW_CACHE_CHECK_INTERVAL > 0 else HourListTaskRunable("customizable userflow cache",settings.USERFLOW_CACHE_CHECK_HOURS)

        #The runable task to check IdentityProvider cache
        self._idp_cache_check_time = IntervalTaskRunable("idp cache",settings.IDP_CACHE_CHECK_INTERVAL) if settings.IDP_CACHE_CHECK_INTERVAL > 0 else HourListTaskRunable("idp cache",settings.IDP_CACHE_CHECK_HOURS)

        #The runable task to check TrafficControl cache
        self._tcontrol_cache_check_time = IntervalTaskRunable("traffic control cache",settings.TRAFFICCONTROL_CACHE_CHECK_INTERVAL) if settings.TRAFFICCONTROL_CACHE_CHECK_INTERVAL > 0 else HourListTaskRunable("traffic control cache",settings.TRAFFICCONTROL_CACHE_CHECK_HOURS)


        self._client = defaultcache.redis_client if defaultcache else None

    _clientdomains_key = None
    @property
    def clientdomains_key(self):
        if not self._clientdomains_key:
            self._clientdomains_key = settings.GET_DEFAULT_CACHE_KEY("clientdomains")
        return self._clientdomains_key
    
    def check_clientdomain(self,domain):
        if any(domain.endswith(d) for d in settings.DOMAIN_WHITELIST):
            return True

        if domain in self._clientdomains:
            return True

        if self._client.sismember(self.clientdomains_key,domain):
            self._clientdomains.add(domain)
            return True
        elif settings.RAISE_EXCEPTION_4_INVALID_DOMAIN:
            raise InvalidDomainException("Redirect to '{}' is strictly forbidden.".format(domain))
        else:
            return False

    def register_clientdomain(self,domain):
        if any(domain.endswith(d) for d in settings.DOMAIN_WHITELIST):
            return

        self._clientdomains.add(domain)
        self._client.sadd(self.clientdomains_key,domain)

    @property
    def usergrouptree(self):
        if not self._usergrouptree:
            self.refresh_usergroups()

        return self._usergrouptree

    @property
    def usergroups(self):
        if not self._usergroups:
            self.refresh_usergroups()

        return self._usergroups

    @property
    def dbca_group(self):
        self.refresh_authorization_cache()
        return self._dbca_group

    @property
    def public_group(self):
        self.refresh_authorization_cache()
        return self._public_group

    @usergrouptree.setter
    def usergrouptree(self,value):
        if value:
            self._usergrouptree,self._usergroups,self._public_group,self._dbca_group,self._usergrouptree_size,self._usergrouptree_ts = value
        else:
            self._usergrouptree,self._usergroups,self._public_group,self._dbca_group,self._usergrouptree_size,self._usergrouptree_ts = None,None,None,None,None,None

    @property
    def usergroupauthorization(self):
        if not self._usergroupauthorization:
            self.refresh_usergroupauthorization()

        return self._usergroupauthorization

    @usergroupauthorization.setter
    def usergroupauthorization(self,value):
        if value:
            self._usergroupauthorization,self._usergroupauthorization_size,self._usergroupauthorization_ts = value
        else:
            self._usergroupauthorization,self._usergroupauthorization_size,self._usergroupauthorization_ts = None,None,None

    def get_authorizations(self,groupskey,domain):
        """
        During authorization, this method is the first method to be invoked, and then the methods 'userauthrizations','usergrouptree' and 'usergroupauthorization' will be invoked if required.
        So only call method 'refresh_authorization_cache' in this method and ignore in other methods 'userauthrizations','usergrouptree' and 'usergroupauthorization'.
        """
        self.refresh_authorization_cache()
        return self._groups_authorization_map.get((groupskey,domain))

    def set_authorizations(self,groupskey,domain,authorizations):
        self._groups_authorization_map[(groupskey,domain)] = authorizations
        self._enforce_maxsize("groups authorization map",self._groups_authorization_map,settings.GROUPS_AUTHORIZATION_CACHE_SIZE)

    @property
    def idps(self):
        self.refresh_idp_cache()
        return self._idps

    @idps.setter
    def idps(self,value):
        if value:
            self._idps,self._idps_size,self._idps_ts = value
        else:
            self._idps,self._idps_size,self._idps_ts = None,None,None

    @property
    def tcontrols(self):
        self.refresh_tcontrol_cache()
        return self._tcontrols

    @tcontrols.setter
    def tcontrols(self,value):
        if value:
            self._tcontrols,self._tcontrols_size,self._tcontrols_ts = value
        else:
            self._tcontrols,self._tcontrols_size,self._tcontrols_ts = None,None,None

    @property
    def userflows(self):
        self.refresh_userflow_cache()
        return self._userflows

    def _find_userflows(self,domain):
        userflows = self._userflows_map.get(domain)
        if not userflows:
            userflows = []
            for o in self._userflows:
                if o.request_domain.match(domain):
                    userflows.append(o)
            if not userflows:
                userflows.append(self._defaultuserflow)
            self._userflows_map[domain] = userflows
        logger.debug("Find the userflow({1}) for domain '{0}'".format(domain,userflows))
        return userflows

    def find_userflows(self,domain=None):
        """
        find matched userflows, if can't find, return default userflow
        if domain is None, return default userflow
        """
        self.refresh_userflow_cache()
        if domain:
            return self._find_userflows(domain)
        else:
            return [self._defaultuserflow]

    def get_userflow(self,domain=None):
        """
        Get the userflow configured for that domain, if can't find, return default userflow
        if domain is None, return default userflow
        """
        self.refresh_userflow_cache()
        if domain:
            return self._find_userflows(domain)[0]
        else:
            return self._defaultuserflow

    @userflows.setter
    def userflows(self,value):
        if value:
            self._userflows,self._defaultuserflow,self._userflows_size,self._userflows_ts = value
        else:
            self._userflows,self._defaultuserflow,self._userflows_size,self._userflows_ts = None,None,None,None

        self._userflows_map.clear()

    def get_groups_key(self,groups):
        """
        Use the same key instance for the same groups
        Return the group  key for the groups
        """
        key = list(g.id for g in groups)
        key.sort()
        key = tuple(key)
        try:
            return self._groupskey_map[key]
        except:
            self._groupskey_map[key] = key
            return key

    def get_email_groupskey(self,email):
        return self._email_groups_map.get(email) or self._public_email_groups_map.get(email)

    def set_email_groups(self,email,groups):
        """
        cache the email and groups mapping
        """
        #get the key of the groups
        groupskey = self.get_groups_key(groups[0])

        #set the map between email and groupskey
        if len(groups[0]) > 1 or groups[0][0] != self._public_group:
            self._email_groups_map[email] = groupskey
            self._enforce_maxsize("email groups map",self._email_groups_map,settings.EMAIL_GROUPS_CACHE_SIZE)
        else:
            self._public_email_groups_map[email] = groupskey
            self._enforce_maxsize("public email groups map",self._public_email_groups_map,settings.PUBLIC_EMAIL_GROUPS_CACHE_SIZE)

        #set the map between groupskey and groups
        if groupskey not in self._groups_map:
            self._groups_map[groupskey] = groups

    def get_email_groups(self,email):
        #try to get the groupskey from email_groups and then from public email groups
        groupskey = self._email_groups_map.get(email) or self._public_email_groups_map.get(email)

        if not groupskey:
            return None

        return self._groups_map.get(groupskey)

    def get_auth(self,user,key,last_modified=None):
        """
        Return the populated http reponse
        """
        data = self._staff_auth_map.get(key) if user.is_staff else self._auth_map.get(key)
        if data:
            if timezone.localtime() <= data[2] and (not last_modified or data[1] >= last_modified):
                return data[0]
            elif user.is_staff:
                del self._staff_auth_map[key]
                return None
            else:
                del self._auth_map[key]
                return None
        else:
            return None

    def set_auth(self,user,key,response):
        """
        cache the auth response content 
        """
        now = timezone.localtime()
        if user.is_staff:
            self._staff_auth_map[key] = [response,now,now + settings.STAFF_AUTH_CACHE_EXPIRETIME ]
            self._enforce_maxsize("staff auth map",self._staff_auth_map,settings.STAFF_AUTH_CACHE_SIZE)
        else:
            self._auth_map[key] = [response,now,now + settings.AUTH_CACHE_EXPIRETIME]
            self._enforce_maxsize("auth map",self._auth_map,settings.AUTH_CACHE_SIZE)

        self.clean_auth_cache()

    def del_auth(self,user,key):
        if not user:
            #try to delete the data from staff cache
            try:
                del self._staff_auth_map[key]
            except KeyError as ex:
                #Can't find the data in staff cache
                #try to delete the data from auth cache
                try:
                    del self._auth_map[key]
                except KeyError as ex:
                    pass

        elif user.is_staff:
            try:
                del self._staff_auth_map[key]
            except KeyError as ex:
                pass
        else:
            try:
                del self._auth_map[key]
            except KeyError as ex:
                pass



    def get_basic_auth_key(self,name_or_email,token):
        return (name_or_email,token)

    def get_basic_auth(self,key):
        """
        Return the populated http reponse
        """
        data = self._basic_auth_map.get(key[0])
        if data:
            if data[1] == key[1] and timezone.localtime() <= data[2]:
                #token is matched and not expired
                return data[0]
            else:
                #token is not matched, remove the data
                del self._basic_auth_map[key[0]]
                return (None,None)
        else:
            #not cached token found
            return (None,None)

    def set_basic_auth(self,user,key,response):
        """
        cache the auth token response content and return the populated http response
        """
        self._basic_auth_map[key[0]] = [(user.id,response),key[1],timezone.localtime() + settings.AUTH_BASIC_CACHE_EXPIRETIME]

        self._enforce_maxsize("token auth map",self._basic_auth_map,settings.BASIC_AUTH_CACHE_SIZE)
        self.clean_auth_cache()

    def delete_basic_auth(self,key):
        try:
            del self._basic_auth_map[key[0]]
        except:
            #not found
            pass

    def _enforce_maxsize(self,name,cache,max_size):
        #clean the oversized data
        oversize = len(cache) - max_size
        if oversize > 0:
            while oversize > 0:
                cache.popitem(last=False)
                oversize -= 1
            logger.debug("Remove earliest data from cache {0} to enforce the maximum cache size {1}".format(name,max_size))

    def _remove_expireddata(self,name,cache):
        #clean the expired data
        cleaned_datas = 0
        now = timezone.localtime()
        more_expired_data = True
        expired_keys =[]
        index = 0
        now = timezone.localtime()
        for k,v in cache.items():
            if now > v[-1]:
                index += 1
            else:
                break
        if index == 0:
            return
        elif index == len(cache):
            cache.clear()
        else:
            while index > 0:
                cache.popitem(last=False)
                index -= 1
            logger.debug("Remove expired datas from cache {0}".format(name))

    def clean_auth_cache(self,force=False):
        if self._auth_cache_clean_time.can_run() or force:
            self._auth_map.clear()
            self._basic_auth_map.clear()

            self._auth_cache_ts = timezone.localtime()

    def refresh_usergroups(self,force=False):
        from ..models import UserGroupChange,UserGroup
        if (force or not self._usergrouptree or UserGroupChange.is_changed()):
            logger.debug("UserGroup was changed, clean cache usergroupptree and user_requests_map")
            self._groups_authorization_map.clear()
            self._groups_authorization_map_ts = timezone.localtime()
            self._email_groups_map.clear()
            self._public_email_groups_map.clear()
            self._groups_map.clear()
            self._emailgroups_ts = timezone.localtime()
            self._groupskey_map.clear()
            #reload group trees
            UserGroup.refresh_cache()

    def refresh_usergroupauthorization(self,force=False):
        from ..models import UserGroupAuthorizationChange,UserGroupAuthorization
        if (force or not self._usergroupauthorization or UserGroupAuthorizationChange.is_changed()):
            logger.debug("UserGroupAuthorization was changed, clean cache usergroupauthorization and user_requests_map")
            self._groups_authorization_map.clear()
            self._groups_authorization_map_ts = timezone.localtime()
            #reload user group requests
            UserGroupAuthorization.refresh_cache()

    def refresh_authorization_cache(self,force=False):
        if self._authorization_cache_check_time.can_run() or force or not self._usergrouptree:
            self.refresh_usergroups(force)
            #self.refresh_userauthorization(force)
            self.refresh_usergroupauthorization(force)

    def refresh_idp_cache(self,force=False):
        if not self._idps:
            from ..models import IdentityProvider
            self._idp_cache_check_time.can_run()
            IdentityProvider.refresh_cache()
        elif self._idp_cache_check_time.can_run() or force:
            from ..models import IdentityProviderChange,IdentityProvider
            if IdentityProviderChange.is_changed():
                IdentityProvider.refresh_cache()

    def refresh_tcontrol_cache(self,force=False):
        if not self._tcontrols:
            from ..models import TrafficControl
            self._tcontrol_cache_check_time.can_run()
            TrafficControl.refresh_cache()
        elif self._tcontrol_cache_check_time.can_run() or force:
            from ..models import TrafficControlChange,TrafficControl
            if TrafficControlChange.is_changed():
                TrafficControl.refresh_cache()

    def refresh_userflow_cache(self,force=False):
        if not self._userflows:
            from ..models import CustomizableUserflow
            self._userflow_cache_check_time.can_run()
            CustomizableUserflow.refresh_cache()
        elif self._userflow_cache_check_time.can_run() or force:
            from ..models import CustomizableUserflowChange,CustomizableUserflow
            if CustomizableUserflowChange.is_changed():
                CustomizableUserflow.refresh_cache()

    @property
    def status(self):
        result = {}
        result["UserGroup"] = {
            "grouptree_cache_size":None if self.usergrouptree is None else len(self.usergrouptree),
            "group_cache_size":None if self.usergroups is None else len(self.usergroups),
            "dbcagroup":str(self.dbca_group),
            "publicgroup":str(self.public_group),
            "latest_refresh_time":utils.format_datetime(self._usergrouptree_ts),
            "next_check_time":utils.format_datetime(self._authorization_cache_check_time.next_runtime)
        }
    
        result["UserGroupAuthorization"] = {
            "cache_size":None if self.usergroupauthorization is None else len(self.usergroupauthorization),
            "latest_refresh_time":utils.format_datetime(self._usergroupauthorization_ts),
            "next_check_time":utils.format_datetime(self._authorization_cache_check_time.next_runtime)
        }
    
        result["CustomizableUserflow"] = {
            "userflow_cache_size":None if self.userflows is None else len(self.userflows),
            "defaultuserflow":str(self._defaultuserflow),
            "domain2userflow_cache_size":None if self._userflows_map is None else len(self._userflows_map),
            "latest_refresh_time":utils.format_datetime(self._userflows_ts),
            "next_check_time":utils.format_datetime(self._userflow_cache_check_time.next_runtime)
        }
    
    
        result["IdentityProvider"] = {
            "cache_size":None if self.idps is None else len(self.idps),
            "latest_refresh_time":utils.format_datetime(self._idps_ts),
            "next_check_time":utils.format_datetime(self._idp_cache_check_time.next_runtime)
        }
    
        result["groupsauthorization"] = {
            "cache_size":None if self._groups_authorization_map is None else len(self._groups_authorization_map),
            "cache_maxsize":settings.GROUPS_AUTHORIZATION_CACHE_SIZE,
            "latest_clean_time":utils.format_datetime(self._groups_authorization_map_ts),
            "next_check_time":utils.format_datetime(self._authorization_cache_check_time.next_runtime)
        }

        auth_responses = {}
        result["auth_responses"] = auth_responses
    
        auth_responses["external_user"] = {
            "cache_size":None if self._auth_map is None else len(self._auth_map),
            "cache_maxsize":settings.AUTH_CACHE_SIZE,
            "latest_clean_time":utils.format_datetime(self._auth_cache_ts),
            "next_clean_time":utils.format_datetime(self._auth_cache_clean_time.next_runtime)
        }
        auth_responses["staff"] = {
            "cache_size":None if self._staff_auth_map is None else len(self._staff_auth_map),
            "cache_maxsize":settings.STAFF_AUTH_CACHE_SIZE,
            "latest_clean_time":utils.format_datetime(self._auth_cache_ts),
            "next_clean_time":utils.format_datetime(self._auth_cache_clean_time.next_runtime)
        }
    
        auth_responses["basic_auth"] = {
            "cache_size":None if self._basic_auth_map is None else len(self._basic_auth_map),
            "cache_maxsize":settings.BASIC_AUTH_CACHE_SIZE,
            "latest_clean_time":utils.format_datetime(self._auth_cache_ts),
            "next_clean_time":utils.format_datetime(self._auth_cache_clean_time.next_runtime)
        }
    
        result["usergroups"] = {
            "usergroups_cache_size":None if self._email_groups_map is None else len(self._email_groups_map),
            "usergroups_cache_maxsize":settings.EMAIL_GROUPS_CACHE_SIZE,
            "publicusergroups_cache_size":None if self._public_email_groups_map is None else len(self._public_email_groups_map),
            "publicusergroups_cache_maxsize":settings.PUBLIC_EMAIL_GROUPS_CACHE_SIZE,
            "groupsmap_size":None if self._groups_map is None else len(self._groups_map),
            "latest_clean_time":utils.format_datetime(self._emailgroups_ts),
            "next_check_time":utils.format_datetime(self._authorization_cache_check_time.next_runtime)
        }
    
        return result

    @property
    def healthy(self):
        msgs = []
        if not self.usergrouptree :
            msgs.append("The UserGroup tree cache is empty")

        if not self.usergroups:
            msgs.append("The UserGroup cache is empty")

        if not self.dbca_group:
            msgs.append("The cached dbca user group is None")

        if not self.public_group:
            msgs.append("The cached public user group is None")

        if not self.usergroupauthorization:
            msgs.append("The UserGroupAuthorization cache is empty.")

        if not self.userflows:
            msgs.append("The CustomizableUserflow cache is empty")

        if not self._defaultuserflow:
            msgs.append("The cached default userflow is None")

        if not self.idps:
            msgs.append("The IdentityProvider cache is empty")

        if self._groups_authorization_map is None :
            msgs.append("The groups authorization cache is None")
            
        if len(self._groups_authorization_map) > (settings.GROUPS_AUTHORIZATION_CACHE_SIZE + 100) :
            msgs.append("The size({}) of the groups authorization cache exceed the maximum cache size({})".format(len(self._groups_authorization_map), settings.GROUPS_AUTHORIZATION_CACHE_SIZE))
            
        if self._auth_map is None  :
            msgs.append("The external user auth responses cache is None")
    
        if len(self._auth_map) > settings.AUTH_CACHE_SIZE + 100 :
            msgs.append("The size({}) of the external user auth responses cache exceed the maximum cache size({})".format(len(self._auth_map), settings.AUTH_CACHE_SIZE))
    
        if self._staff_auth_map is None  :
            msgs.append("The staff auth responses cache is None")
    
        if len(self._staff_auth_map) > settings.STAFF_AUTH_CACHE_SIZE + 100 :
            msgs.append("The size({}) of the staff auth responses cache exceed the maximum cache size({})".format(len(self._staff_auth_map), settings.STAFF_AUTH_CACHE_SIZE))
    
        if self._basic_auth_map is None :
            msgs.append("The basic auth response cache is None")
    
        if len(self._basic_auth_map) > settings.BASIC_AUTH_CACHE_SIZE + 100 :
            msgs.append("The size({}) of the basic auth response cache exceed the maximum cache size({})".format(len(self._basic_auth_map), settings.BASIC_AUTH_CACHE_SIZE))
    
        if self._email_groups_map is None:
            msgs.append("The email groups map cache is None")
    
        if len(self._email_groups_map) > settings.EMAIL_GROUPS_CACHE_SIZE + 100:
            msgs.append("The size({}) of the user groups map cache exceed the maximum cache size({})".format(len(self._email_groups_map), settings.EMAIL_GROUPS_CACHE_SIZE))
    
        if self._public_email_groups_map is None:
            msgs.append("The public user groups map cache is None")
    
        if len(self._public_email_groups_map) > settings.PUBLIC_EMAIL_GROUPS_CACHE_SIZE + 100:
            msgs.append("The size({}) of the public user groups map cache exceed the maximum cache size({})".format(len(self._public_email_groups_map), settings.PUBLIC_EMAIL_GROUPS_CACHE_SIZE))
    
        if self._groups_map is None:
            msgs.append("The groups map cache is None")
    
        return (False,msgs) if msgs else (True,["ok"])

if settings.TRAFFIC_MONITOR_LEVEL > 0:
    def _clean_traffic_data(data):
        for key in data.keys():
            if isinstance(data[key],dict):
                _clean_traffic_data(data[key])
            else:
                data[key] = 0
        
    class _MemoryCacheWithTrafficMonitor(_BaseMemoryCache):
        def __init__(self):
            super().__init__()
            self._traffic_data = None
            now = timezone.localtime()
            today = datetime(now.year,now.month,now.day,tzinfo=now.tzinfo)
            seconds_in_day = (now - today).seconds
            self._traffic_data_ts = today + timedelta(seconds =  seconds_in_day - seconds_in_day % settings.TRAFFIC_MONITOR_INTERVAL.seconds)
            self._traffic_data_next_ts = self._traffic_data_ts + settings.TRAFFIC_MONITOR_INTERVAL
    
        _traffic_data_key = None
        @property
        def traffic_data_key(self):
            if not self._traffic_data_key:
                self._traffic_data_key = settings.GET_DEFAULT_CACHE_KEY("traffic-data")
            return self._traffic_data_key
    
        @property
        def traffic_data_key_pattern(self):
            return settings.GET_DEFAULT_CACHE_KEY("traffic-data-level{}-{}-{{}}".format(settings.TRAFFIC_MONITOR_LEVEL,settings.TRAFFIC_MONITOR_INTERVAL.seconds))

        def _save_traffic_data(self,start):
            data_starttime = utils.format_datetime(self._traffic_data_ts)
            data_endtime = utils.format_datetime(self._traffic_data_next_ts)
            seconds = (start - self._traffic_data_next_ts).seconds
            self._traffic_data_ts = self._traffic_data_next_ts + timedelta(seconds = seconds - seconds % settings.TRAFFIC_MONITOR_INTERVAL.seconds)
            self._traffic_data_next_ts = self._traffic_data_ts + settings.TRAFFIC_MONITOR_INTERVAL
            if self._traffic_data :
                self._traffic_data["starttime"] = data_starttime
                self._traffic_data["endtime"] = data_endtime
                traffic_data = json.dumps(self._traffic_data)

                for data in self._traffic_data.values():
                    if not isinstance(data,dict):
                        continue
                    _clean_traffic_data(data)
    
                try:
                    length = self._client.rpush(self.traffic_data_key,traffic_data)
                except:
                    from authome.models import DebugLog
                    DebugLog.warning(DebugLog.ERROR,None,None,None,None,"Failed to save the traffic data to cache.{}".format(traceback.format_exc()))
                    pass

        def _log_request_1(self,name,group,start,status_code,groupname="domains"):
            if start >= self._traffic_data_next_ts:
                self._save_traffic_data(start)
    
            ptime = round((timezone.localtime() - start).total_seconds() * 1000,2)
            try:
                data = self._traffic_data[name]
            except KeyError as ex:
                # name not in _traffic_data
                self._traffic_data[name] = {
                    "requests":1,
                    "totaltime":ptime,
                    "mintime":ptime,
                    "maxtime":ptime,
                    "status":{
                        status_code:1
                    }
                }
                return ptime
            except:
                #_traffic_data is None
                self._traffic_data= {
                    "serverid":utils.get_processid(),
                    name: {
                        "requests":1,
                        "totaltime":ptime,
                        "mintime":ptime,
                        "maxtime":ptime,
                        "status":{
                           status_code:1
                        }
                    }
                }
                return ptime
            data["requests"] += 1
            data["totaltime"] += ptime
            if not data["mintime"]  or data["mintime"] > ptime:
                data["mintime"] = ptime
            if data["maxtime"] < ptime:
                data["maxtime"] = ptime
            data["status"][status_code] = data["status"].get(status_code,0) + 1
            return ptime

        def _log_request_2(self,name,group,start,status_code,groupname="domains"):
            if start >= self._traffic_data_next_ts:
                self._save_traffic_data(start)
    
            ptime = round((timezone.localtime() - start).total_seconds() * 1000,2)
            try:
                data = self._traffic_data[name]
            except KeyError as ex:
                # name not in _traffic_data
                self._traffic_data[name] = {
                    "requests":1,
                    "totaltime":ptime,
                    "mintime":ptime,
                    "maxtime":ptime,
                    "status":{
                        status_code:1
                    },
                    groupname: {
                        group : 1
                    }
                }
                return ptime
            except:
                #_traffic_data is None
                self._traffic_data = {
                    "serverid":utils.get_processid(),
                    name: {
                        "requests":1,
                        "totaltime":ptime,
                        "mintime":ptime,
                        "maxtime":ptime,
                        "status":{
                            status_code:1
                        },
                        groupname: {
                            group : 1
                        }
                    }
                }
                return ptime
            data["requests"] += 1
            data["totaltime"] += ptime
            if not data["mintime"]  or data["mintime"] > ptime:
                data["mintime"] = ptime
            if data["maxtime"] < ptime:
                data["maxtime"] = ptime
            data["status"][status_code] = data["status"].get(status_code,0) + 1
            data[groupname][group] = data[groupname].get(group,0) + 1
            return ptime

        def _log_request_3(self,name,group,start,status_code,groupname="domains"):
            if start >= self._traffic_data_next_ts:
                self._save_traffic_data(start)
    
            ptime = round((timezone.localtime() - start).total_seconds() * 1000,2)
            try:
                data = self._traffic_data[name]
            except KeyError as ex:
                # name not in _traffic_data
                self._traffic_data[name] = {
                    "requests":1,
                    "totaltime":ptime,
                    "mintime":ptime,
                    "maxtime":ptime,
                    "status":{
                        status_code:1
                    },
                    groupname: {
                        group : {
                            "requests":1,
                            "totaltime":ptime,
                            "mintime":ptime,
                            "maxtime":ptime,
                            "status":{
                                status_code:1
                            }
                        }
                    }
                }
                return ptime
            except:
                # _traffic_data is None
                self._traffic_data = {
                    "serverid":utils.get_processid(),
                    name: {
                        "requests":1,
                        "totaltime":ptime,
                        "mintime":ptime,
                        "maxtime":ptime,
                        "status":{
                            status_code:1
                        },
                        groupname: {
                            group : {
                                "requests":1,
                                "totaltime":ptime,
                                "mintime":ptime,
                                "maxtime":ptime,
                                "status":{
                                    status_code:1
                                }
                            }
                        }
                    }
                }
                return ptime
    
            data["requests"] += 1
            data["totaltime"] += ptime
            if not data["mintime"]  or data["mintime"] > ptime:
                data["mintime"] = ptime
            if data["maxtime"] < ptime:
                data["maxtime"] = ptime
            data["status"][status_code] = data["status"].get(status_code,0) + 1
            try:
                group_data = data[groupname][group]
                group_data["requests"] += 1
                group_data["totaltime"] += ptime
                if not group_data["mintime"]  or group_data["mintime"] > ptime:
                    group_data["mintime"] = ptime
                if group_data["maxtime"] < ptime:
                    group_data["maxtime"] = ptime
                group_data["status"][status_code] = group_data["status"].get(status_code,0) + 1
            except:
                group_data = {
                    "requests":1,
                    "totaltime":ptime,
                    "mintime":ptime,
                    "maxtime":ptime,
                    "status":{
                        status_code:1
                    }
                }
                data[groupname][group] = group_data
    
            return ptime

    if settings.TRAFFIC_MONITOR_LEVEL == 1:
        logger.debug("Traffic monitor level 1 is enabled")
        _MemoryCacheWithTrafficMonitor.log_request = _MemoryCacheWithTrafficMonitor._log_request_1
    elif settings.TRAFFIC_MONITOR_LEVEL == 2:
        logger.debug("Traffic monitor level 2 is enabled")
        _MemoryCacheWithTrafficMonitor.log_request = _MemoryCacheWithTrafficMonitor._log_request_2
    else:
        logger.debug("Traffic monitor level 3 is enabled")
        _MemoryCacheWithTrafficMonitor.log_request = _MemoryCacheWithTrafficMonitor._log_request_3

    if settings.REDIS_TRAFFIC_MONITOR_LEVEL == 1:
        logger.debug("Reids traffic monitor level 1 is enabled")
        _MemoryCacheWithTrafficMonitor.log_redisrequest = _MemoryCacheWithTrafficMonitor._log_request_1
    elif settings.REDIS_TRAFFIC_MONITOR_LEVEL == 2:
        logger.debug("Reids traffic monitor level 2 is enabled")
        _MemoryCacheWithTrafficMonitor.log_redisrequest = _MemoryCacheWithTrafficMonitor._log_request_2
    elif settings.REDIS_TRAFFIC_MONITOR_LEVEL > 0:
        logger.debug("Reids traffic monitor level 3 is enabled")
        _MemoryCacheWithTrafficMonitor.log_redisrequest = _MemoryCacheWithTrafficMonitor._log_request_3

    if settings.DB_TRAFFIC_MONITOR_LEVEL == 1:
        logger.debug("DB traffic monitor level 1 is enabled")
        _MemoryCacheWithTrafficMonitor.log_dbrequest = _MemoryCacheWithTrafficMonitor._log_request_1
    elif settings.DB_TRAFFIC_MONITOR_LEVEL == 2:
        logger.debug("DB traffic monitor level 2 is enabled")
        _MemoryCacheWithTrafficMonitor.log_dbrequest = _MemoryCacheWithTrafficMonitor._log_request_2
    elif settings.DB_TRAFFIC_MONITOR_LEVEL > 0:
        logger.debug("DB traffic monitor level 3 is enabled")
        _MemoryCacheWithTrafficMonitor.log_dbrequest = _MemoryCacheWithTrafficMonitor._log_request_3

    if settings.SYNC_MODE in ("sync","gevent","eventlet"):
        class MemoryCache(_MemoryCacheWithTrafficMonitor):
            def __init__(self):
                super().__init__()
                logger.info("Traffic monitor is running in single thread mode")
    else:
        #running in thread-safe has a big performance penalty
        import threading
        class MemoryCache(_MemoryCacheWithTrafficMonitor):
            def __init__(self):
                super().__init__()
                logger.info("Traffic monitor is running in thread-safe mode")

            def log_request(self,name,host,start,status_code):
                logger.debug("Traffic monitor is running in thread-safe mode")
                with threading.Lock():
                    return super().log_request(name,host,start,status_code)
else:
    class MemoryCache(_BaseMemoryCache):
        pass

