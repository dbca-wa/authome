import logging
import traceback

from django.conf import settings
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY

from django.utils.crypto import  get_random_string

from .. import models
from .. import utils
from ..cache import cache as auth2cache
from . import sessionstore
from .. import performance

logger = logging.getLogger(__name__)

class StandaloneSessionStore(sessionstore.SessionStore):
    cache_key_prefix = "{}:session:".format(settings.STANDALONE_CACHE_KEY_PREFIX) if settings.STANDALONE_CACHE_KEY_PREFIX else "session:"

class SessionStore(sessionstore.SessionStore):
    """
    The following requirements must be met if upgrading a standalone auth2 server to cluster server, 
    1. Cache servers used by auth2 should be same
    2. If previous session cache is enabled, it will be shared by standalone auth2 server and cluster auth2 server
    but the cache key prefix can be different.

    """
    standalone_cache_key_prefix = "{}:session:".format(settings.STANDALONE_CACHE_KEY_PREFIX) if settings.STANDALONE_CACHE_KEY_PREFIX else "session:"
    SIGNATURE_LEN = utils.LB_HASH_KEY_DIGEST_SIZE * 2
    _cookie_changed = None
    def __init__(self, lb_hash_key,auth2_clusterid,session_key):
        super().__init__(session_key)
        self._lb_hash_key = lb_hash_key
        self._auth2_clusterid = auth2_clusterid

    @property
    def standalone_cache_key(self):
        return self.standalone_cache_key_prefix + self.session_key

    @classmethod
    def standalone_cache_key(cls,session_key):
        return cls.standalone_cache_key_prefix + session_key

    def get_session_cookie_age(self,session_cookie=None):
        """
        Return different session cookie age for authenticated session and anonymous session
        """
        if session_cookie:
            lb_hash_key,auth2_clusterid,session_key = session_cookie.split("|",2)
        else:
            session_key = self._session_key
        if session_key and "-" in session_key:
            return settings.SESSION_COOKIE_AGE
        else:
            return settings.GUEST_SESSION_AGE

    @classmethod
    def check_integrity(cls,lb_hash_key,auth2_clusterid,session_key):
        sig = utils.sign_lb_hash_key(lb_hash_key,auth2_clusterid,settings.LB_HASH_KEY_SECRET)
        if session_key[-2 - len(sig):-2] != sig:
            if settings.PREVIOUS_LB_HASH_KEY_SECRET:
                sig = utils.sign_lb_hash_key(hash_key,auth2_clusterid,settings.PREVIOUS_LB_HASH_KEY_SECRET)
                if session_key[-2 - len(sig):-2] != sig:
                    return False
            else:
                return False

        return True

    def _get_session_key(self):
        return self.__session_key

    def _set_session_key(self, value):
        """
        Validate session key on assignment. Invalid values will set to None.
        """
        if self._cookie_changed is None:
            self._cookie_changed = False
        else:
            self._cookie_changed = True
            self._auth2_clusterid = settings.AUTH2_CLUSTERID

        if self._validate_session_key(value):
            self.__session_key = value
        else:
            self.__session_key = None

    session_key = property(_get_session_key)
    _session_key = property(_get_session_key, _set_session_key)

    @property
    def cookie_changed(self):
        return self._cookie_changed

    @property
    def cookie_value(self):
        #should be only called if session is not empty
        return "{}|{}|{}".format(self._lb_hash_key,settings.AUTH2_CLUSTERID,self.session_key or self.expired_session_key)

    def load(self):
        if self._auth2_clusterid == settings.AUTH2_CLUSTERID:
            #local cluster session 
            return super().load()
        session_data = None
        if not self._auth2_clusterid and auth2cache.current_auth2_cluster.default:
            #sessionid created in the same auth2 server,
            #upgrade the session to cluster session
            try:
                performance.start_processingstep("upgrade_to_cluster_session")
                standalone_sessionstore = StandaloneSessionStore(self._session_key)
                try:
                    performance.start_processingstep("get_old_session_from_cache")
                    session_data = standalone_sessionstore.load()
                finally:
                    performance.end_processingstep("get_old_session_from_cache")
                    pass
                sig = utils.sign_lb_hash_key(self._lb_hash_key,settings.AUTH2_CLUSTERID,settings.LB_HASH_KEY_SECRET)
                new_session_key = "{}{}{}".format(self._session_key[:-2],sig,self._session_key[-2:])
                if session_data:
                    self._session_key = new_session_key
                    newcachekey = self.cache_key
                    sessioncache = self._get_cache()

                    if session_data.get("migrated",False):
                        #already migrated, load the session directly
                        try:
                            performance.start_processingstep("get_cluster_session_from_cache")
                            session_data = sessioncache.get(newcachekey)
                        finally:
                            performance.end_processingstep("get_cluster_session_from_cache")
                            pass
                    else:
                        timeout = session_data.get("session_timeout")
                        if timeout and session_data.get(USER_SESSION_KEY):
                            try:
                                performance.start_processingstep("set_cluster_session_to_cache")
                                sessioncache.set(newcachekey,session_data,timeout)
                            finally:
                                performance.end_processingstep("set_cluster_session_to_cache")
                                pass
                        else:
                            try:
                                performance.start_processingstep("get_old_session_ttl_from_cache")
                                ttl = standalone_sessioncache.ttl
                            except:
                                ttl = None
                            finally:
                                performance.end_processingstep("get_old_session_ttl_from_cache")
                                pass
    
                            try:
                                performance.start_processingstep("set_cluster_session_to_cache")
                                if ttl:
                                    sessioncache.set(newcachekey,session_data,ttl)
                                else:
                                    sessioncache.set(newcachekey,session_data,self.get_session_age())
                            finally:
                                performance.end_processingstep("set_cluster_session_to_cache")
                                pass
                        try:
                            performance.start_processingstep("mark_old_session_as_migrated")
                            standalone_sessionstore.mark_as_migrated()
                            sessioncache.set(cachekey,{"migrated":True},settings.MIGRATED_SESSION_TIMEOUT)
                        finally:
                            performance.end_processingstep("mark_old_session_as_migrated")
                            pass
            except Exception as ex:
                logger.error("Failed to load session.{}".format(str(ex)))
                raise
            finally:
                performance.end_processingstep("upgrade_to_cluster_session")
                pass
        else:
            #session should be migrated from original server to current server
            try:
                performance.start_processingstep("migrate_session_from_other_cluster")
                original_auth2_clusterid = self._auth2_clusterid
                original_session_key = self._session_key
                try:
                    performance.start_processingstep("load_session_from_other_cluster")
                    session = auth2cache.get_remote_session(original_auth2_clusterid,original_session_key,False)
                finally:
                    performance.end_processingstep("load_session_from_other_cluster")
                    pass

                if session:
                    sig = utils.sign_lb_hash_key(self._lb_hash_key,settings.AUTH2_CLUSTERID,settings.LB_HASH_KEY_SECRET)
                    if self._auth2_clusterid:
                        self._session_key = "{}{}{}".format(self._session_key[:-2-self.SIGNATURE_LEN],sig,self._session_key[-2:])
                    else:
                        #sessionid created in the auth2 server without cluster support
                        #current auth2 cluster is not the default cluster
                        self._session_key = "{}{}{}".format(self._session_key[:-2],sig,self._session_key[-2:])
                    cachekey = self.cache_key
                    sessioncache = self._get_cache()

                    session_data = session["session"]
                    if session_data.get("migrated",False):
                        #already migrated, load the session directly
                        try:
                            performance.start_processingstep("load_cluster_session_from_cache")
                            session_data = sessioncache.get(cachekey)
                            logger.debug("Load the migrated session .{}".format(session_data))
                        finally:
                            performance.end_processingstep("load_cluster_session_from_cache")
                            pass
                    else:
                        timeout = session_data.get("session_timeout")
                        try:
                            performance.start_processingstep("save_session_to_cache")
                            if timeout and session_data.get(USER_SESSION_KEY):
                                sessioncache.set(cachekey,session_data,timeout)
                            else:
                                ttl = session.get("ttl")
                                if ttl:
                                    sessioncache.set(cachekey,session_data,ttl)
                                else:
                                    sessioncache.set(cachekey,session_data,self.get_session_age())
                        finally:
                            performance.end_processingstep("save_session_to_cache")
                            pass

                        #remove the user from cache to refresh the user data from migrated session
                        userid = session_data.get(USER_SESSION_KEY)
                        if userid:
                            try:
                                performance.start_processingstep("remove_user_from_usercache")
                                userid = int(userid)
                                usercache = get_usercache(userid)
                                if usercache:
                                    usercache.delete(settings.GET_USER_KEY(userid))
                            except:
                                pass
                            finally:
                                performance.end_processingstep("remove_user_from_usercache")
                                pass

                            
                        #mark the session as migrated session in original cache server
                        try:
                            performance.start_processingstep("mark_remote_session_as_migrated")
                            auth2cache.mark_remote_session_as_migrated(original_auth2_clusterid ,original_session_key,False)
                        finally:
                            performance.end_processingstep("mark_remote_session_as_migrated")
                            pass
                    return session_data
                else:
                    session_data = None
            except Exception as ex:
                logger.error("Failed to load session.{}".format(str(ex)))
                raise
            finally:
                performance.end_processingstep("migrate_session_from_other_cluster")
                pass

        if session_data is not None:
            return session_data
    
        #expired authenticated session, or session does not exist
        if self._session_key and "-" in self._session_key:
            #this is a authenticated session key
            self.expired_session_key = new_session_key
        self._session_key = None
        return {}

    def populate_session_key(self,process_prefix,idpid):
        sig = utils.sign_lb_hash_key(self._lb_hash_key,settings.AUTH2_CLUSTERID,settings.LB_HASH_KEY_SECRET)
        if idpid:
            return "{5}-{1}{0}{2}{4}{3}".format(
                process_prefix,
                get_random_string(16, sessionstore.VALID_KEY_CHARS),
                get_random_string(14, sessionstore.VALID_KEY_CHARS),
                get_random_string(2, sessionstore.VALID_KEY_CHARS),
                sig,
                idpid
            )
        else:
            return "{1}{0}{2}{4}{3}".format(
                process_prefix,
                get_random_string(16, sessionstore.VALID_KEY_CHARS),
                get_random_string(14, sessionstore.VALID_KEY_CHARS),
                get_random_string(2, sessionstore.VALID_KEY_CHARS),
                sig
            )

