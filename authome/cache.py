import traceback
import logging
import time
from collections import OrderedDict

from django.core.cache import caches
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

try:
    ssocache = cachese["ssocache"]
except:
    logger.info("SSO cache is not configured, use memory cache instead")
    ssocache = None

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
    
        self._user_authorization_map = {} if settings.AUTHORIZATION_CACHE_SIZE <= 0 else OrderedDict() 
    
        self._auth_map = OrderedDict() 
        self._token_auth_map = OrderedDict() 

        self._next_check_authorization_cache = None
        self._next_remove_expired_authdata = timezone.now() + settings.AUTH_CACHE_EXPIRETIME
        self._next_remove_expired_tokenauthdata = timezone.now() + settings.TOKEN_AUTH_CACHE_EXPIRETIME

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

    def get_auth_key(self,email,session_key):
        return session_key

    def get_auth(self,key):
        try:
            data = self._auth_map.pop(key)
            if settings.AUTH_CACHE_EXPIRETIME:
                data[1] = timezone.now() + settings.AUTH_CACHE_EXPIRETIME
                self._auth_map[key] = data
                return data[0]
            else:
                self._auth_map[key] = data
                return data
        except KeyError as ex:
            return None

    def set_auth(self,key,value):
        if settings.AUTH_CACHE_EXPIRETIME:
            self._auth_map[key] = [value,timezone.now() + settings.AUTH_CACHE_EXPIRETIME]
        else:
            self._auth_map[key] = value

        if settings.AUTH_CACHE_SIZE > 0:
            self._enforce_maxsize("auth map",self._auth_map,settings.AUTH_CACHE_SIZE)
        self.remove_expired_authdata()

    def update_auth(self,key,value):
        try:
            data = self._auth_map.pop(key)
            if settings.AUTH_CACHE_EXPIRETIME:
                data[0] = value
                data[1] = timezone.now() + settings.AUTH_CACHE_EXPIRETIME
            else:
                data = value
        except KeyError as ex:
            if settings.AUTH_CACHE_EXPIRETIME:
                data = [value,timezone.now() + settings.AUTH_CACHE_EXPIRETIME]
            else:
                data = value

        self._auth_map[key] = data


    def delete_auth(self,key):
        try:
            del self._auth_map[key]
        except:
            #not found
            pass

    def get_token_auth_key(self,name_or_email,token):
        return (name_or_email,token)

    def get_token_auth(self,key):
        try:
            data = self._token_auth_map.pop(key[0])
            if data[1] == key[1]:
                #token is matched
                if settings.TOKEN_AUTH_CACHE_EXPIRETIME :
                    data[2] = timezone.now() + settings.TOKEN_AUTH_CACHE_EXPIRETIME
                #readd the key to ordereddict
                self._token_auth_map[key[0]] = data
                return data[0]
            else:
                #token is not matched, and is already removed,
                return None
        except KeyError as ex:
            #not cached token found
            return None

    def set_token_auth(self,key,value):
        if not settings.TOKEN_AUTH_CACHE_EXPIRETIME :
            self._token_auth_map[key[0]] = [value,key[1]]
        else:
            self._token_auth_map[key[0]] = [value,key[1],timezone.now() + settings.TOKEN_AUTH_CACHE_EXPIRETIME]

        if settings.TOKEN_AUTH_CACHE_SIZE > 0:
            self._enforce_maxsize("token auth map",self._token_auth_map,settings.TOKEN_AUTH_CACHE_SIZE)
        self.remove_expired_tokenauthdata()

    def update_token_auth(self,key,value):
        self.delete_token_auth(key)
        self.set_token_auth(key,value)
        try:
            data = self._token_auth_map.pop(key[0])
            if data[1] == key[1]:
                #token is matched
                if settings.TOKEN_AUTH_CACHE_EXPIRETIME :
                    data[2] = timezone.now() + settings.TOKEN_AUTH_CACHE_EXPIRETIME
                #readd the key to ordereddict
                self._token_auth_map[key[0]] = data
                return data[0]
            else:
                #token is not matched, and is already removed,
                return None
        except KeyError as ex:
            #not cached token found
            return None

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
            logger.debug("Remove earliest data from cache {0} to enforce the maximum cache size {}".format(name,max_size))

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

    def remove_expired_authdata(self):
        if timezone.now() >= self._next_remove_expired_authdata:
            self._remove_expireddata('auth map',self._auth_map)
            self._next_remove_expired_authdata = timezone.now() + settings.AUTH_CACHE_EXPIRETIME

    def remove_expired_tokenauthdata(self):
        if timezone.now() >= self._next_remove_expired_tokenauthdata:
            self._remove_expireddata('token auth map',self._token_auth_map)
            self._next_remove_expired_tokenauthdata = timezone.now() + settings.TOKEN_AUTH_CACHE_EXPIRETIME

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
        if force or not self._next_check_authorization_cache or timezone.now() >= self._next_check_authorization_cache:
            self.refresh_usergrouptree(force)
            self.refresh_userauthorization(force)
            self.refresh_usergroupauthorization(force)
            self._next_check_authorization_cache = timezone.now() + settings.AUTHORIZATION_CACHE_DELAY

_cache = MemoryCache()
def get_cache():
    return _cache

        


