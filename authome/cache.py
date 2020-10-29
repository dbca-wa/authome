import threading
import logging
import time

from django.core.cache import caches
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

class _Cache(object):
    _usergrouptree = None
    _usergrouptree_ts = None

    _userauthorization = None
    _userauthorization_ts = None

    _usergroupauthorization = None
    _usergroupauthorization_ts = None

    _user_requests_map = {}

    @property
    def usergrouptree(self):
        if self._usergrouptree :
            from .models import UserGroup
            if UserGroup.objects.filter(modified__gt=self._usergrouptree_ts).exists():
                self._usergrouptree = None
                self._usergrouptree_ts = None

        return self._usergrouptree

    @usergrouptree.setter
    def usergrouptree(self,value):
        self._usergrouptree = value
        self._usergrouptree_ts = timezone.now()
        
    @property
    def userauthorization(self):
        if self._userauthorization :
            from .models import UserAuthorization
            if UserAuthorization.objects.filter(modified__gt=self._userauthorization_ts).exists():
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
            if UserGroupAuthorization.objects.filter(modified__gt=self._usergroupauthorization_ts).exists():
                self._usergroupauthorization = None
                self._usergroupauthorization_ts = None

        return self._usergroupauthorization

    @usergroupauthorization.setter
    def usergroupauthorization(self,value):
        self._usergroupauthorization = value
        self._usergroupauthorization_ts = timezone.now()
        
    def get_requests(self,user,domain):
        requests = self._user_requests_map.get((user,domain))
        if requests :
            from .models import UserGroupAuthorization,UserAuthorization,UserGroup
            if self._usergrouptree and UserGroup.objects.filter(modified__gt=self._usergrouptree_ts).exists():
                self._user_requests_map.clear()
                self._usergrouptree = None
                self._usergrouptree_ts = None
                requests = None
            elif self._usergroupauthorization and UserGroupAuthorization.objects.filter(modified__gt=self._usergroupauthorization_ts).exists():
                self._user_requests_map.clear()
                self._usergroupauthorization = None
                self._usergroupauthorization_ts = None
                requests = None
            elif self._userauthorization and UserAuthorization.objects.filter(modified__gt=self._userauthorization_ts).exists():
                self._user_requests_map.clear()
                self._userauthorization = None
                self._userauthorization_ts = None
                requests = None

        return requests

    def set_requests(self,user,domain,requests):
        self._user_requests_map[(user,domain)] = requests

    def refresh(self,force=False):
        if force:
            self._usergrouptree = None
            self._usergrouptree_ts = None
    
            self._userauthorization = None
            self._userauthorization_ts = None
    
            self._usergroupauthorization = None
            self._usergroupauthorization_ts = None
    
            self._user_requests_map.clear()


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
        self._usergrouptree = value
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
        
    def get_requests(self,user,domain):
        return self._user_requests_map.get((user,domain))

    def refresh(self,force=False):
        from .models import UserGroup,UserAuthorization,UserGroupAuthorization
        if force or not cache._usergrouptree or UserGroup.objects.filter(modified__gt=cache._usergrouptree_ts).exists():
            logger.debug("UserGroup was changed, clean cache usergroupptree and user_requests_map")
            cache._usergrouptree = None
            cache._usergrouptree_ts = None
            cache._user_requests_map.clear()
            #reload group trees
            get_grouptree = UserGroup.get_grouptree()


        if force or not cache._userauthorization or UserAuthorization.objects.filter(modified__gt=cache._userauthorization_ts).exists():
            logger.debug("UserAuthorization was changed, clean cache userauthorization and user_requests_map")
            cache._userauthorization = None
            cache._userauthorization_ts = None
            cache._user_requests_map.clear()
            #reload user requests
            UserAuthorization.get_requests(None)

        if force or not cache._usergroupauthorization or UserGroupAuthorization.objects.filter(modified__gt=cache._usergroupauthorization_ts).exists():
            logger.debug("UserGroupAuthorization was changed, clean cache usergroupauthorization and user_requests_map")
            cache._usergroupauthorization = None
            cache._usergroupauthorization_ts = None
            cache._user_requests_map.clear()
            #reload user group requests
            UserGroupAuthorization.get_requests(None)

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

        


