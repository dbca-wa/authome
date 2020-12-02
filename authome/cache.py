import traceback
import logging
import time
from datetime import datetime,timedelta
from collections import OrderedDict

from django.core.cache import caches
from django.conf import settings
from django.utils import timezone
from django.http import HttpResponse

logger = logging.getLogger(__name__)

class IntervalTaskRunTime(object):
    """
    Interval is the number of seconds between the continuous run of a task
    A day can divided by a valid interval.
    """
    def __init__(self,name,interval):
        self._name = name
        self._interval = interval
        self._next_time = None

    def can_run(self,dt=None):
        if dt:
            dt = timezone.localtime(dt)
        else:
            dt = timezone.localtime()

        if not self._next_time:
            today = datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo) 
            self._next_time = today + timedelta(seconds = (int((dt - today).seconds / self._interval) + 1) * self._interval)
            logger.debug("No need to run task({}), next runtime is {}".format(self._name,self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        elif self._next_time > dt:
            logger.debug("No need to run task({}), next runtime is {}".format(self._name,self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        else:
            today = datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo) 
            self._next_time = today + timedelta(seconds = (int((dt - today).seconds / self._interval) + 1) * self._interval)
            logger.debug("Run task({}) now, next runtime is {}".format(self._name,self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return True

class TaskRunTime(object):
    def __init__(self,name,hours):
        self._name = name
        self._next_time = None
        self._index = None
        self._hours = hours
        if len(self._hours) == 1:
            self._timediffs = [timedelta(hours=24)]
        else:
            self._timediffs = []

        i = 0
        while i < len(self._hours):
            if i == 0:
                self._timediffs.append(timedelta(hours=24 + self._hours[i] - self._hours[-1]))
            else:
                self._timediffs.append(timedelta(hours=self._hours[i] - self._hours[i-1]))
            i += 1

    def can_run(self,dt=None):
        if dt:
            dt = timezone.localtime(dt)
        else:
            dt = timezone.localtime()

        if not self._next_time:
            self._index = 0
            self._next_time = datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo) + timedelta(hours=self._hours[0])
            while self._next_time <= dt:
                if self._index == len(self._hours) - 1:
                    self._index = 0
                else:
                    self._index += 1
                self._next_time += self._timediffs[self._index]
            logger.debug("No need to run task({}), next runtime is {}".format(self._name,self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        elif self._next_time > dt:
            logger.debug("No need to run task({}), next runtime is {}".format(self._name,self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        else:
            while self._next_time <= dt:
                if self._index == len(self._hours) - 1:
                    self._index = 0
                else:
                    self._index += 1
                self._next_time += self._timediffs[self._index]
            logger.debug("Run task({}) now, next runtime is {}".format(self._name,self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return True

class MemoryCache(object):
    def __init__(self):
        super().__init__()
        self._usergrouptree = None
        self._dbca_group = None
        self._public_group = None
        self._usergrouptree_size = None
        self._usergrouptree_ts = None
    
        self._userauthorization = None
        self._userauthorization_size = None
        self._userauthorization_ts = None
    
        self._usergroupauthorization = None
        self._usergroupauthorization_size = None
        self._usergroupauthorization_ts = None
    
        self._user_authorization_map = OrderedDict() 
    
        self._auth_map = OrderedDict() 
        self._basic_auth_map = OrderedDict() 

        self._idps = None
        self._idps_size = None
        self._idps_ts = None

        #start the cache refresh timer
        self._auth_cache_clean_time = TaskRunTime("authentication cache",settings.AUTH_CACHE_CLEAN_HOURS)
        self._authorization_cache_check_time = IntervalTaskRunTime("authorization cache",settings.AUTHORIZATION_CACHE_CHECK_INTERVAL) if settings.AUTHORIZATION_CACHE_CHECK_INTERVAL > 0 else TaskRunTime("authorization cache",settings.AUTHORIZATION_CACHE_CHECK_HOURS) 
        self._idp_cache_check_time = IntervalTaskRunTime("idp cache",settings.IDP_CACHE_CHECK_INTERVAL) if settings.IDP_CACHE_CHECK_INTERVAL > 0 else TaskRunTime("idp cache",settings.IDP_CACHE_CHECK_HOURS) 

    @property
    def usergrouptree(self):
        self.refresh_authorization_cache()
        return self._usergrouptree

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
            self._usergrouptree,self._public_group,self._dbca_group,self._usergrouptree_size,self._usergrouptree_ts = value
        else:
            self._usergrouptree,self._public_group,self._dbca_group,self._usergrouptree_size,self._usergrouptree_ts = None,None,None,None
        
    @property
    def userauthorization(self):
        return self._userauthorization

    @userauthorization.setter
    def userauthorization(self,value):
        if value:
            self._userauthorization,self._userauthorization_size,self._userauthorization_ts = value
        else:
            self._userauthorization,self._userauthorization_size,self._userauthorization_ts = None,None,None

    @property
    def usergroupauthorization(self):
        return self._usergroupauthorization

    @usergroupauthorization.setter
    def usergroupauthorization(self,value):
        if value:
            self._usergroupauthorization,self._usergroupauthorization_size,self._usergroupauthorization_ts = value
        else:
            self._usergroupauthorization,self._usergroupauthorization_size,self._usergroupauthorization_ts = None,None,None
        
    def get_authorization(self,user,domain):
        self.refresh_authorization_cache()
        return self._user_authorization_map.get((user,domain))

    def set_authorization(self,user,domain,requests):
        self._user_authorization_map[(user,domain)] = requests
        self._enforce_maxsize("user authorization map",self._user_authorization_map,settings.AUTHORIZATION_CACHE_SIZE)

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


    def get_auth_key(self,email,session_key):
        return session_key

    def get_auth(self,key):
        """
        Return the populated http reponse
        """
        data = self._auth_map.get(key)
        if data:
            if timezone.now() <= data[1]:
                return data[0]
            else:
                del self._auth_map[key]
                return None
        else:
            return None

    def set_auth(self,key,response):
        """
        cache the auth response content and return the populated http response 
        """
        self._auth_map[key] = [response,timezone.now() + settings.AUTH_CACHE_EXPIRETIME]

        self._enforce_maxsize("auth map",self._auth_map,settings.AUTH_CACHE_SIZE)
        self.clean_auth_cache()

    def update_auth(self,key,response):
        """
        cache the updated auth response content and return the populated http response 
        """
        data = self._auth_map.get(key)
        if data:
            data[0] = response
        else:
            self._auth_map[key] = [response,timezone.now() + settings.AUTH_CACHE_EXPIRETIME]

    def delete_auth(self,key):
        try:
            del self._auth_map[key]
        except:
            #not found
            pass

    def get_basic_auth_key(self,name_or_email,token):
        return (name_or_email,token)

    def get_basic_auth(self,key):
        """
        Return the populated http reponse
        """
        data = self._basic_auth_map.get(key[0])
        if data:
            if data[1] == key[1] and timezone.now() <= data[2]:
                #token is matched and not expired
                return data[0]
            else:
                #token is not matched, remove the data
                del self._basic_auth_map[key[0]]
                return None
        else:
            #not cached token found
            return None

    def set_basic_auth(self,key,response):
        """
        cache the auth token response content and return the populated http response 
        """
        self._basic_auth_map[key[0]] = [response,key[1],timezone.now() + settings.AUTH_BASIC_CACHE_EXPIRETIME]

        self._enforce_maxsize("token auth map",self._basic_auth_map,settings.AUTH_BASIC_CACHE_SIZE)
        self.clean_auth_cache()

    def update_basic_auth(self,key,response):
        """
        cache the updated auth token response content and return the populated http response 
        """
        data = self._basic_auth_map.get(key[0])
        if data:
            if data[1] == key[1] and timezone.now() <= data[2]:
                #token is matched
                data[0] = response
            else:
                #token is not matched, remove the old one, add a new one
                del self._basic_auth_map[key[0]]
                self._basic_auth_map[key[0]] = [response,key[1],timezone.now() + settings.AUTH_BASIC_CACHE_EXPIRETIME]
        else:
            #not cached token found
            self._basic_auth_map[key[0]] = [response,key[1],timezone.now() + settings.AUTH_BASIC_CACHE_EXPIRETIME]

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
        now = timezone.now()
        more_expired_data = True
        expired_keys =[]
        index = 0
        now = timezone.now()
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

    def refresh_usergroups(self,force=False):
        from .models import UserGroup
        if (force or 
            not self._usergrouptree or 
            UserGroup.objects.filter(modified__gt=self._usergrouptree_ts).exists() or
            UserGroup.objects.all().count() != self._usergrouptree_size
        ):
            logger.debug("UserGroup was changed, clean cache usergroupptree and user_requests_map")
            self._user_authorization_map.clear()
            #reload group trees
            UserGroup.refresh_usergroups()


    def refresh_userauthorization(self,force=False):
        from .models import UserAuthorization
        if (force or 
            not self._userauthorization or 
            UserAuthorization.objects.filter(modified__gt=self._userauthorization_ts).exists() or  
            UserAuthorization.objects.all().count() != self._userauthorization_size
        ):
            logger.debug("UserAuthorization was changed, clean cache userauthorization and user_requests_map")
            self._user_authorization_map.clear()
            #reload user requests
            UserAuthorization.refresh_authorization()

    def refresh_usergroupauthorization(self,force=False):
        from .models import UserGroupAuthorization
        if (force or 
            not self._usergroupauthorization or 
            UserGroupAuthorization.objects.filter(modified__gt=self._usergroupauthorization_ts).exists() or
            UserGroupAuthorization.objects.all().count() != self._usergroupauthorization_size
        ):
            logger.debug("UserGroupAuthorization was changed, clean cache usergroupauthorization and user_requests_map")
            self._user_authorization_map.clear()
            #reload user group requests
            UserGroupAuthorization.refresh_authorization()

    def refresh_authorization_cache(self,force=False):
        if self._authorization_cache_check_time.can_run() or force:
            self.refresh_usergroups()
            self.refresh_userauthorization()
            self.refresh_usergroupauthorization()

    def refresh_idp_cache(self,force=False):
        if self._idp_cache_check_time.can_run() or force:
            from .models import IdentityProvider
            if ( not self._idps or 
                IdentityProvider.objects.filter(modified__gt=self._idps_ts).exists() or  
                IdentityProvider.objects.all().count() != self._idps_size
            ):
                IdentityProvider.refresh_idps()


cache = MemoryCache()
