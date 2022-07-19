import logging

from django.conf import settings
from django.utils import timezone
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY

from .. import utils
from .. import sessionstore
from .. import performance
from . import sessionstore

logger = logging.getLogger(__name__)

class SessionStoreDebugMixin(object):
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

            if not session_data:
                if settings.PREVIOUS_SESSION_CACHES > 0:
                    #Try to find the session from previous sesstion cache
                    previous_sessioncache = self._get_previous_cache(self.session_key)
                    performance.start_processingstep("migrate_session_from_previous_cache")
                    try:
                        performance.start_processingstep("get_session_from_previous_session_cache")
                        try:
                            session_data = previous_sessioncache.get(cachekey)
                        finally:
                            performance.end_processingstep("get_session_from_previous_session_cache")
                            pass
                        if session_data:
                            if session_data.get("migrated",False):
                                #already migrated, load the session again.
                                try:
                                    performance.start_processingstep("get_session_from_cache")
                                    session_data = sessioncache.get(cachekey)
                                finally:
                                    performance.end_processingstep("get_session_from_cache")
                                    pass
                            else:
                                timeout = session_data.get("session_timeout")
                                if timeout and session_data.get(USER_SESSION_KEY):
                                    performance.start_processingstep("save_session_to_session_cache")
                                    try:
                                        sessioncache.set(cachekey,session_data,timeout)
                                    finally:
                                        performance.end_processingstep("save_session_to_session_cache")
                                        pass
                                else:
                                    performance.start_processingstep("get_ttl_from_previous_session_cache")
                                    try:
                                        ttl = previous_sessioncache.ttl(cachekey)
                                    except:
                                        ttl = None
                                    finally:
                                        performance.end_processingstep("get_ttl_from_previous_session_cache")
                                        pass
        
                                    performance.start_processingstep("save_session_to_session_cache")
                                    try:
                                        if ttl:
                                            sessioncache.set(cachekey,session_data,ttl)
                                        else:
                                            sessioncache.set(cachekey,session_data,self.get_session_age())
                                    finally:
                                        performance.end_processingstep("save_session_to_session_cache")
                                        pass
                                #mark the session as migrated session in previous cache
                                previous_sessioncache.set(previous_cachekey,{"migrated":True},60)

                    finally:
                        performance.end_processingstep("migrate_session_from_previous_cache")
                        pass
            else:
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

class SessionStore(SessionStoreDebugMixin,sessionstore.SessionStore):
    pass
