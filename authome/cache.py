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
    def __init__(self,interval):
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
            logger.debug("No need to run task, next runtime is {}".format(self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        elif self._next_time > dt:
            logger.debug("No need to run task, next runtime is {}".format(self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        else:
            today = datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo) 
            self._next_time = today + timedelta(seconds = (int((dt - today).seconds / self._interval) + 1) * self._interval)
            logger.debug("Run task now, next runtime is {}".format(self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return True

class TaskRunTime(object):
    def __init__(self,hours):
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
            logger.debug("No need to run task, next runtime is {}".format(self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        elif self._next_time > dt:
            logger.debug("No need to run task, next runtime is {}".format(self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return False
        else:
            while self._next_time <= dt:
                if self._index == len(self._hours) - 1:
                    self._index = 0
                else:
                    self._index += 1
                self._next_time += self._timediffs[self._index]
            logger.debug("Run task now, next runtime is {}".format(self._next_time.strftime("%Y-%m-%d %H:%M:%S")))
            return True

class MemoryCache(object):
    def __init__(self):
        super().__init__()
        self._usergrouptree = None
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
        self._token_auth_map = OrderedDict() 

        self._auth_cache_clean_time = TaskRunTime(settings.AUTH_CACHE_CLEAN_HOURS)
        self._authorization_cache_check_time = IntervalTaskRunTime(settings.AUTHORIZATION_CACHE_CHECK_INTERVAL) if settings.AUTHORIZATION_CACHE_CHECK_INTERVAL > 0 else TaskRunTime(settings.AUTHORIZATION_CACHE_CHECK_HOURS) 

    def populate_response(self,content):
        response = HttpResponse(content[0], content_type='application/json')
        for key, val in content[1].items():
            response[key] = val
        return response

    def populate_response_from_cache(self,content):
        response = self.populate_response(content)
        response["X-auth-cache-hit"] = "success"
        return response

    @property
    def usergrouptree(self):
        return self._usergrouptree

    @usergrouptree.setter
    def usergrouptree(self,value):
        if value:
            self._usergrouptree,self._usergrouptree_size,self._usergrouptree_ts = value
        else:
            self._usergrouptree,self._usergrouptree_size,self._usergrouptree_ts = None,None,None
        
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

    def set_auth(self,key,value):
        """
        cache the auth response content and return the populated http response 
        """
        res = self.populate_response(value)
        cached_res = self.populate_response_from_cache(value)
        
        self._auth_map[key] = [cached_res,timezone.now() + settings.AUTH_CACHE_EXPIRETIME]

        self._enforce_maxsize("auth map",self._auth_map,settings.AUTH_CACHE_SIZE)
        self.clean_auth_cache()
        return res

    def update_auth(self,key,value):
        """
        cache the updated auth response content and return the populated http response 
        """
        res= self.populate_response_from_cache(value)
        data = self._auth_map.get(key)
        if data:
            data[0] = res
        else:
            self._auth_map[key] = [res,timezone.now() + settings.AUTH_CACHE_EXPIRETIME]
        return res

    def delete_auth(self,key):
        try:
            del self._auth_map[key]
        except:
            #not found
            pass

    def get_token_auth_key(self,name_or_email,token):
        return (name_or_email,token)

    def get_token_auth(self,key):
        """
        Return the populated http reponse
        """
        data = self._token_auth_map.get(key[0])
        if data:
            if data[1] == key[1] and timezone.now() <= data[2]:
                #token is matched and not expired
                return data[0]
            else:
                #token is not matched, remove the data
                del self._token_auth_map[key[0]]
                return None
        else:
            #not cached token found
            return None

    def set_token_auth(self,key,value):
        """
        cache the auth token response content and return the populated http response 
        """
        res = self.populate_response(value)
        cached_res = self.populate_response_from_cache(value)
        
        self._token_auth_map[key[0]] = [cached_res,key[1],timezone.now() + settings.AUTH_TOKEN_CACHE_EXPIRETIME]

        self._enforce_maxsize("token auth map",self._token_auth_map,settings.AUTH_TOKEN_CACHE_SIZE)
        self.clean_auth_cache()

        return res

    def update_token_auth(self,key,value):
        """
        cache the updated auth token response content and return the populated http response 
        """
        res= self.populate_response_from_cache(value)
        data = self._token_auth_map.get(key[0])
        if data:
            if data[1] == key[1] and timezone.now() <= data[2]:
                #token is matched
                data[0] = res
            else:
                #token is not matched, remove the old one, add a new one
                del self._token_auth_map[key[0]]
                self._token_auth_map[key[0]] = [res,key[1],timezone.now() + settings.AUTH_TOKEN_CACHE_EXPIRETIME]
        else:
            #not cached token found
            self._token_auth_map[key[0]] = [res,key[1],timezone.now() + settings.AUTH_TOKEN_CACHE_EXPIRETIME]

        return res

    def delete_token_auth(self,key):
        try:
            del self._token_auth_map[key[0]]
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
            self._token_auth_map.clear()

    def refresh_usergrouptree(self,force=False):
        from .models import UserGroup
        if (force or 
            not self._usergrouptree or 
            UserGroup.objects.filter(modified__gt=self._usergrouptree_ts).exists() or
            UserGroup.objects.all().count() != self._usergrouptree_size
        ):
            logger.debug("UserGroup was changed, clean cache usergroupptree and user_requests_map")
            self._user_authorization_map.clear()
            #reload group trees
            get_grouptree = UserGroup.get_grouptree(True)


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
            UserAuthorization.get_authorization(None,refresh=True)

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
            UserGroupAuthorization.get_authorization(None,refresh=True)

    def refresh_authorization_cache(self,force=False):
        if self._authorization_cache_check_time.can_run() or force:
            self.refresh_usergrouptree(force)
            self.refresh_userauthorization(force)
            self.refresh_usergroupauthorization(force)

cache = MemoryCache()

        


