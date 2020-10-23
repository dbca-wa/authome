import threading
import logging
import atexit

from django.core.cache import caches
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

KEY_USER_GROUP_TREE = "UserGroupTree"
KEY_USER_REQUESTS = "UserRequests"
KEY_USERGROUP_REQUESTS = "UserGroupRequests"
KEY_USER_REQUEST_MAP = "UserRequestMap"

def is_local_cache_expired(key):
    cache_ts = _local_cache_timestamp.get(key)
    if not cache_ts:
        return True

    if not authorization_cache:
        if key == KEY_USER_GROUP_TREE:
            return False
            from .models import UserGroup
            data_ts = UserGroup.objects.all().order_by("-modified").first().modified.timestamp()
        else:
            data_ts = None
            return False
    else:
        data_ts = cache.get(key)
        if not data_ts:
            data_ts = None

    return cache_ts != data_ts

def set_local_cache_ts(key,ts=None):
    if not ts:
        ts = timezone.now().timestamp()
    else:
        ts = ts.timestamp()

    _local_cache_timestamp[key] = ts

class _CheckThread(threading.Thread):
    _request_shutdown = False
    def __init__(self):
        super().__init__()
        self._lock = threading.Condition(threading.Lock())

    def shutdown(self):
        logger.info("Request to shutdown authorization cache checking thread")
        self._request_shutdown= True
        try:
            self._lock.acquire(blocking=True)
            self._lock.notify_all()
        except:
            pass
        finally:
            self._lock.release()

        if self.is_alive():
            try:
                self.join()
            except:
                pass
        logger.info("The authorization cache checking thread stopped")

    def run(self):
        index = 0
        while not self._request_shutdown:
            try:
                self._lock.acquire(blocking=True)
                self._lock.wait(settings.AUTHORIZATION_CACHE_DELAY)
            except:
                pass
            finally:
                self._lock.release()

            if self._request_shutdown:
                break
            index += 1
            logger.debug("{}: Check whether the authorization caches are expired or not".format(index))
            from .models import UserGroup,UserRequests,UserGroupRequests
            if cache._usergrouptree:
                if UserGroup.objects.filter(modified__gt=cache._usergrouptree_ts).exists():
                    logger.debug("UserGroup was changed, clean cache usergroupptree and user_requests_map")
                    cache._usergrouptree = None
                    cache._usergrouptree_ts = None
                    cache._user_requests_map.clear()
    
            if cache._userrequests:
                if UserRequests.objects.filter(modified__gt=cache._userrequests_ts).exists():
                    logger.debug("UserRequests was changed, clean cache userrequests and user_requests_map")
                    cache._userrequests = None
                    cache._userrequests_ts = None
                    cache._user_requests_map.clear()
    
            if cache._usergrouprequests:
                if UserGroupRequests.objects.filter(modified__gt=cache._usergrouprequests_ts).exists():
                    logger.debug("UserGroupRequests was changed, clean cache usergrouprequests and user_requests_map")
                    cache._usergrouprequests = None
                    cache._usergrouprequests_ts = None
                    cache._user_requests_map.clear()

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
        if self._usergrouptree and settings.AUTHORIZATION_CACHE_DELAY == 0:
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
        if self._userrequests and settings.AUTHORIZATION_CACHE_DELAY == 0:
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
        if self._usergrouprequests and settings.AUTHORIZATION_CACHE_DELAY == 0:
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
        if requests and settings.AUTHORIZATION_CACHE_DELAY == 0:
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


class _DelayCache(_Cache):
    def __init__(self):
        super().__init__()
        self._check_thread = _CheckThread()
        self._check_thread.start()
        atexit.register(self._check_thread.shutdown)

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

    def get_requests(self,user,domain):
        return self._user_requests_map.get((user,domain))


cache = _Cache() if settings.AUTHORIZATION_CACHE_DELAY == 0 else _DelayCache()

        


