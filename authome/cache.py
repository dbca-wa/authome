import threading
import logging
import time

from django.core.cache import caches
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

class _Cache(object):
    _usergrouptree = None
    _usergroupsize = None
    _usergrouptree_ts = None

    _userauthorization = None
    _userauthorization_ts = None

    _usergroupauthorization = None
    _usergroupauthorization_ts = None

    _user_authoriaztion_map = {}

    @property
    def usergrouptree(self):
        if self._usergrouptree :
            from .models import UserGroup
            if (UserGroup.objects.filter(modified__gt=self._usergrouptree_ts).exists() or
                UserGroup.objects.all().count() != self._usergroupsize
            ):
                self._usergrouptree = None
                self._usergroupsize = None
                self._usergrouptree_ts = None

        return self._usergrouptree

    @usergrouptree.setter
    def usergrouptree(self,value):
        self._usergrouptree,self._usergroupsize = value
        self._usergrouptree_ts = timezone.now()
        
    @property
    def userauthorization(self):
        if self._userauthorization :
            from .models import UserAuthorization
            if (UserAuthorization.objects.filter(modified__gt=self._userauthorization_ts).exists() or
               UserAuthorization.objects.all().count() != self._userauthorization["__size__"]
            ):
                self._userauthorization = None
                self._userauthorization_ts = None

        return self._userauthorization

    @userauthorization.setter
    def userauthorization(self,value):
        self._userauthorization = value
        self._userauthorization_ts = timezone.now()
        
    @property
    def usergroupauthorization(self):
        if self._usergroupauthorization :
            from .models import UserGroupAuthorization
            if (UserGroupAuthorization.objects.filter(modified__gt=self._usergroupauthorization_ts).exists() or
               UserGroupAuthorization.objects.all().count() != self._usergroupauthorization["__size__"]
            ):
                self._usergroupauthorization = None
                self._usergroupauthorization_ts = None

        return self._usergroupauthorization

    @usergroupauthorization.setter
    def usergroupauthorization(self,value):
        self._usergroupauthorization = value
        self._usergroupauthorization_ts = timezone.now()
        
    def get_authorization(self,user,domain):
        requests = self._user_authoriaztion_map.get((user,domain))
        if requests :
            from .models import UserGroupAuthorization,UserAuthorization,UserGroup
            if (self._usergrouptree and 
                (
                    UserGroup.objects.filter(modified__gt=self._usergrouptree_ts).exists() or
                    UserGroup.objects.all().count() != self._usergroupsize
                )
            ):
                self._user_authoriaztion_map.clear()
                self._usergrouptree = None
                self._usergrouptree_ts = None
                requests = None
            elif (self._usergroupauthorization and 
                 (
                     UserGroupAuthorization.objects.filter(modified__gt=self._usergroupauthorization_ts).exists() or
                     UserGroupAuthorization.objects.all().count() != self._usergroupauthorization["__size__"]
                 )
            ):
                self._user_authoriaztion_map.clear()
                self._usergroupauthorization = None
                self._usergroupauthorization_ts = None
                requests = None
            elif (self._userauthorization and 
                 (
                     UserAuthorization.objects.filter(modified__gt=self._userauthorization_ts).exists() or
                     UserAuthorization.objects.all().count() != self._userauthorization["__size__"]
                )
            ):
                self._user_authoriaztion_map.clear()
                self._userauthorization = None
                self._userauthorization_ts = None
                requests = None

        return requests

    def set_authorization(self,user,domain,requests):
        self._user_authoriaztion_map[(user,domain)] = requests

    def refresh(self,force=False):
        if force:
            self._usergrouptree = None
            self._usergrouptree_ts = None
    
            self._userauthorization = None
            self._userauthorization_ts = None
    
            self._usergroupauthorization = None
            self._usergroupauthorization_ts = None
    
            self._user_authoriaztion_map.clear()


class _DelayCache(_Cache):
    def __init__(self):
        super().__init__()
        self._check_thread = threading.Thread(target=self.check,daemon=True)
        self._check_thread.start()

    @property
    def usergrouptree(self):
        return self._usergrouptree

    @usergrouptree.setter
    def usergrouptree(self,value):
        self._usergrouptree,self._usergroupsize = value
        self._usergrouptree_ts = timezone.now()
        
    @property
    def userauthorization(self):
        return self._userauthorization

    @userauthorization.setter
    def userauthorization(self,value):
        self._userauthorization = value
        self._userauthorization_ts = timezone.now()

    @property
    def usergroupauthorization(self):
        return self._usergroupauthorization

    @usergroupauthorization.setter
    def usergroupauthorization(self,value):
        self._usergroupauthorization = value
        self._usergroupauthorization_ts = timezone.now()
        
    def get_authorization(self,user,domain):
        return self._user_authoriaztion_map.get((user,domain))

    def refresh(self,force=False):
        from .models import UserGroup,UserAuthorization,UserGroupAuthorization
        if (force or 
            not self._usergrouptree or 
            UserGroup.objects.filter(modified__gt=self._usergrouptree_ts).exists() or
            UserGroup.objects.all().count() != self._usergroupsize
        ):
            logger.debug("UserGroup was changed, clean cache usergroupptree and user_requests_map")
            self._usergrouptree = None
            self._usergrouptree_ts = None
            self._usergroupsize = None
            self._user_authoriaztion_map.clear()
            #reload group trees
            get_grouptree = UserGroup.get_grouptree()


        if (force or 
            not self._userauthorization or 
            UserAuthorization.objects.filter(modified__gt=self._userauthorization_ts).exists() or  
            UserAuthorization.objects.all().count() != self._userauthorization["__size__"]
        ):
            logger.debug("UserAuthorization was changed, clean cache userauthorization and user_requests_map")
            self._userauthorization = None
            self._userauthorization_ts = None
            self._user_authoriaztion_map.clear()
            #reload user requests
            UserAuthorization.get_authorization(None)

        if (force or 
            not self._usergroupauthorization or 
            UserGroupAuthorization.objects.filter(modified__gt=self._usergroupauthorization_ts).exists() or
            UserGroupAuthorization.objects.all().count() != self._usergroupauthorization["__size__"]
        ):
            logger.debug("UserGroupAuthorization was changed, clean cache usergroupauthorization and user_requests_map")
            self._usergroupauthorization = None
            self._usergroupauthorization_ts = None
            self._user_authoriaztion_map.clear()
            #reload user group requests
            UserGroupAuthorization.get_authorization(None)

    def check(self):
        index = 0
        while True:
            index += 1
            logger.debug("{}: Check whether the authorization caches are expired or not".format(index))
            self.refresh()
            try:
                time.sleep(settings.AUTHORIZATION_CACHE_DELAY)
            except:
                break


cache = _Cache() if settings.AUTHORIZATION_CACHE_DELAY == 0 else _DelayCache()

        


