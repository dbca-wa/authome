import logging

from django.conf import settings
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY

from django.utils.crypto import  get_random_string

from .. import models
from .. import utils
from ..cache import cache as auth2cache
from . import sessionstore

logger = logging.getLogger(__name__)

class SessionStore(sessionstore.SessionStore):
    SIGNATURE_LEN = utils.LB_HASH_KEY_DIGEST_SIZE * 2
    _cookie_changed = None
    def __init__(self, lb_hash_key,auth2_clusterid,session_key):
        self._original_auth2_clusterid = auth2_clusterid or auth2cache.default_auth2_cluster.clusterid
        self._original_session_key = session_key
        super().__init__(session_key)
        self._lb_hash_key = lb_hash_key
        self._auth2_clusterid = auth2_clusterid

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

    def mark_as_migrated(self):
        cachekey = self.cache_key
        sessioncache = self._get_cache()
        sessioncache.set(cachekey,{"migrated",True},60)


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
            return super().load()
        elif not self._auth2_clusterid and auth2cache.current_auth2_cluster.default:
            #sessionid created in the auth2 server without cluster support
            #current auth2 cluster is the default cluster
            cachekey = self.cache_key
            sessioncache = self._get_cache()
            session_data = sessioncache.get(cachekey)
            sig = utils.sign_lb_hash_key(self._lb_hash_key,settings.AUTH2_CLUSTERID,settings.LB_HASH_KEY_SECRET)
            new_session_key = "{}{}{}".format(self._session_key[:-2],sig,self._session_key[-2:])
            if session_data:
                self._session_key = new_session_key
                newcachekey = self.cache_key
                if session_data.get("migrated",False):
                    #already migrated, load the session directly
                    session_data = sessioncache.get(newcachekey)
                else:
                    #migrate the session from standalone server to cluster server
                    #the last two chars are used to choose the redis cache
                    timeout = session_data.get("session_timeout")
                    if timeout and session_data.get(USER_SESSION_KEY):
                        sessioncache.set(newcachekey,session_data,timeout)
                    else:
                        try:
                            ttl = sessioncache.ttl(cachekey)
                        except:
                            ttl = None
                        if ttl:
                            sessioncache.set(newcachekey,session_data,ttl)
                        else:
                            sessioncache.set(newcachekey,session_data,self.get_session_age())
                    #mark the session as migrated session in previous cache
                    logger.debug("mark the session as migrated 'The session({}) with cache key({})'".format(self._original_session_key,cachekey))
                    sessioncache.set(cachekey,{"migrated":True},60)
                return session_data
            else:
                #expired authenticated session, or session does not exist
                if self._session_key and "-" in self._session_key:
                    #this is a authenticated session key
                    self.expired_session_key = new_session_key
                self._session_key = None
                return {}
        else:
            #session should be migrated from original server to current server
            session = auth2cache.get_remote_session(self._auth2_clusterid or auth2cache.default_auth2_cluster.clusterid,self._session_key,False)
            if session:
                #Found the session
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
                    session_data = sessioncache.get(cachekey)
                else:
                    timeout = session_data.get("session_timeout")
                    sig = utils.sign_lb_hash_key(self._lb_hash_key,settings.AUTH2_CLUSTERID,settings.LB_HASH_KEY_SECRET)
                    if self._auth2_clusterid:
                        self._session_key = "{}{}{}".format(self._session_key[:-2-self.SIGNATURE_LEN],sig,self._session_key[-2:])
                    else:
                        #sessionid created in the auth2 server without cluster support
                        #current auth2 cluster is not the default cluster
                        self._session_key = "{}{}{}".format(self._session_key[:-2],sig,self._session_key[-2:])
                    cachekey = self.cache_key
                    sessioncache = self._get_cache()
                    if timeout and session_data.get(USER_SESSION_KEY):
                        sessioncache.set(cachekey,session_data,timeout)
                    else:
                        ttl = session.get("ttl")
                        if ttl:
                            sessioncache.set(cachekey,session_data,ttl)
                        else:
                            sessioncache.set(cachekey,session_data,self.get_session_age())
                    #mark the session as migrated session in original cache server
                    auth2cache.mark_remote_session_as_migrated(self._auth2_clusterid or auth2cache.default_auth2_cluster.clusterid,self._original_session_key,False)

                return session_data
            else:
                #Can't get the session from original auth2 cluster, 
                #maybe the auth2 cluster is not available, don't log the user out, and try to automatically log the user in again via existing b2c session
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


    def delete(self, session_key=None):
        super().delete(session_key)
        if self._original_auth2_clusterid != settings.AUTH2_CLUSTERID and self._original_session_key and (session_key is None or session_key == self.session_key):
            #delete the current user session, and also the session is migrated from other auth2 cluster, delete the session from original auth2 cluster
            session = auth2cache.delete_remote_session(self._original_auth2_clusterid ,self._original_session_key)
