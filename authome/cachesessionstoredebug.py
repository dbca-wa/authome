import logging

from django.conf import settings
from django.utils import timezone
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY

import authome.cachesessionstore
logger = logging.getLogger(__name__)

from . import performance

class SessionStore(authome.cachesessionstore.SessionStore):
    """
    Override the cache session store to provide the performance related log
    """
    def _get_new_session_key(self):
        "Return session key that isn't being used."
        session_key = super()._get_new_session_key()
        logger.debug("Create a new session key {}".format(session_key))
        return session_key

    def load(self):
        try:
            try:
                performance.start_processingstep("get_session_from_cache")
                sessioncache = self._get_cache()
                cachekey = self.cache_key
                session_data = sessioncache.get(cachekey)
            finally:
                performance.end_processingstep("get_session_from_cache")
                pass

            timeout = session_data.get("session_timeout")
            if timeout and session_data.get(USER_SESSION_KEY):
                if hasattr(sessioncache,"expire"):
                    performance.start_processingstep("set_sessiontimeout_in_cache")
                    try:
                        sessioncache.expire(cachekey,timeout)
                    finally:
                        performance.end_processingstep("set_sessiontimeout_in_cache")
                        pass
                        
        except Exception:
            # Some backends (e.g. memcache) raise an exception on invalid
            # cache keys. If this happens, reset the session. See #17810.
            session_data = None
        if session_data is not None:
            return session_data
        if self._session_key and "-" in self._session_key:
            #this is a authenticated session key
            self.expired_session_key = self._session_key
        self._session_key = None
        return {}

    def create(self):
        try:
            performance.start_processingstep("create_session")
            return super().create()
        finally:
            performance.end_processingstep("create_session")
            logger.debug("Add a new session({}) for {} into cache".format(self.session_key,self.get(USER_SESSION_KEY,'GUEST')))
            pass

        
    def save(self, must_create=False):
        try:
            performance.start_processingstep("save_session_in_cache")
            return super().save(must_create=must_create)
        finally:
            performance.end_processingstep("save_session_in_cache")
            logger.debug("Save a session({}) for {} into cache".format(self.session_key,self.get(USER_SESSION_KEY,'GUEST')))
            pass


    def delete(self, session_key=None):
        try:
            performance.start_processingstep("delete_session_from_cache")
            return super().delete(session_key=session_key)
        finally:
            performance.end_processingstep("delete_session_from_cache")
            logger.debug("Delete a session({}) for {} from cache".format(session_key or self.session_key,self.get(USER_SESSION_KEY,'GUEST')))
            pass

    def exists(self, session_key):
        try:
            performance.start_processingstep("check_exists_in_cache")
            return super().exists(session_key)
        finally:
            performance.end_processingstep("check_exists_in_cache")
            pass
