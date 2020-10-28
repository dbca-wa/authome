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

    _userrequests = None
    _userrequests_ts = None

    _usergrouprequests = None
    _usergrouprequests_ts = None

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
    def userrequests(self):
        if self._userrequests :
            from .models import UserRequests
            if UserRequests.objects.filter(modified__gt=self._userrequests_ts).exists():
                self._userrequests = None
                self._userrequests_ts = None

        return self._userrequests

    @userrequests.setter
    def userrequests(self,value):
        self._userrequests = value
        self._userrequests_ts = timezone.now()
        
    @property
    def usergrouprequests(self):
        if self._usergrouprequests :
            from .models import UserGroupRequests
            if UserGroupRequests.objects.filter(modified__gt=self._usergrouprequests_ts).exists():
                self._usergrouprequests = None
                self._usergrouprequests_ts = None

        return self._usergrouprequests

    @usergrouprequests.setter
    def usergrouprequests(self,value):
        self._usergrouprequests = value
        self._usergrouprequests_ts = timezone.now()
        
    def get_requests(self,user,domain):
        requests = self._user_requests_map.get((user,domain))
        if requests :
            from .models import UserGroupRequests,UserRequests,UserGroup
            if self._usergrouptree and UserGroup.objects.filter(modified__gt=self._usergrouptree_ts).exists():
                self._user_requests_map.clear()
                self._usergrouptree = None
                self._usergrouptree_ts = None
                requests = None
            elif self._usergrouprequests and UserGroupRequests.objects.filter(modified__gt=self._usergrouprequests_ts).exists():
                self._user_requests_map.clear()
                self._usergrouprequests = None
                self._usergrouprequests_ts = None
                requests = None
            elif self._userrequests and UserRequests.objects.filter(modified__gt=self._userrequests_ts).exists():
                self._user_requests_map.clear()
                self._userrequests = None
                self._userrequests_ts = None
                requests = None

        return requests

    def set_requests(self,user,domain,requests):
        self._user_requests_map[(user,domain)] = requests

    def refresh(self,force=False):
        if force:
            self._usergrouptree = None
            self._usergrouptree_ts = None
    
            self._userrequests = None
            self._userrequests_ts = None
    
            self._usergrouprequests = None
            self._usergrouprequests_ts = None
    
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
    def userrequests(self):
        return self._userrequests

    @userrequests.setter
    def userrequests(self,value):
        self._userrequests = value
        self._userrequests_ts = timezone.now()

    @property
    def usergrouprequests(self):
        return self._usergrouprequests

    @usergrouprequests.setter
    def usergrouprequests(self,value):
        self._usergrouprequests = value
        self._usergrouprequests_ts = timezone.now()
        
    def get_requests(self,user,domain):
        return self._user_requests_map.get((user,domain))

    def refresh(self,force=False):
        from .models import UserGroup,UserRequests,UserGroupRequests
        if force or not cache._usergrouptree or UserGroup.objects.filter(modified__gt=cache._usergrouptree_ts).exists():
            logger.debug("UserGroup was changed, clean cache usergroupptree and user_requests_map")
            cache._usergrouptree = None
            cache._usergrouptree_ts = None
            cache._user_requests_map.clear()
            #reload group trees
            get_grouptree = UserGroup.get_grouptree()


        if force or not cache._userrequests or UserRequests.objects.filter(modified__gt=cache._userrequests_ts).exists():
            logger.debug("UserRequests was changed, clean cache userrequests and user_requests_map")
            cache._userrequests = None
            cache._userrequests_ts = None
            cache._user_requests_map.clear()
            #reload user requests
            UserRequests.get_requests(None)

        if force or not cache._usergrouprequests or UserGroupRequests.objects.filter(modified__gt=cache._usergrouprequests_ts).exists():
            logger.debug("UserGroupRequests was changed, clean cache usergrouprequests and user_requests_map")
            cache._usergrouprequests = None
            cache._usergrouprequests_ts = None
            cache._user_requests_map.clear()
            #reload user group requests
            UserGroupRequests.get_requests(None)

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

        


