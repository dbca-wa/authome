import logging

from django.conf import settings
from django.utils import timezone
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY

from ..cache import cache as auth2cache
from .. import utils
from .. import performance
from . import clustersessionstore
from .sessionstoredebug import SessionStoreDebugMixin

logger = logging.getLogger(__name__)

class SessionStore(SessionStoreDebugMixin,clustersessionstore.SessionStore):
    def load(self):
        if self._auth2_clusterid == settings.AUTH2_CLUSTERID:
            return super().load()
        elif not self._auth2_clusterid and auth2cache.current_auth2_cluster.default:
            #sessionid created in the auth2 server without cluster support
            #current auth2 cluster is the default cluster
            try:
                performance.start_processingstep("upgrade_to_cluster_session")
                cachekey = self.cache_key
                sessioncache = self._get_cache()
                try:
                    performance.start_processingstep("get_old_session_from_cache")
                    session_data = sessioncache.get(cachekey)
                finally:
                    performance.end_processingstep("get_old_session_from_cache")
                    pass
                sig = utils.sign_lb_hash_key(self._lb_hash_key,settings.AUTH2_CLUSTERID,settings.LB_HASH_KEY_SECRET)
                new_session_key = "{}{}{}".format(self._session_key[:-2],sig,self._session_key[-2:])
                if session_data:
                    self._session_key = new_session_key
                    newcachekey = self.cache_key
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
                            ttl = sessioncache.ttl(cachekey)
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
                    return session_data
                else:
                    #expired authenticated session, or session does not exist
                    if self._session_key and "-" in self._session_key:
                        #this is a authenticated session key
                        self.expired_session_key = new_session_key
                    self._session_key = None
                    return {}
            finally:
                performance.end_processingstep("upgrade_to_cluster_session")
                pass
        else:
            #session should be migrated from original server to current server
            try:
                performance.start_processingstep("migrate_session_from_other_cluster")
                try:
                    performance.start_processingstep("get_session_from_other_cluster")
                    session = auth2cache.get_remote_session(self._auth2_clusterid or auth2cache.default_auth2_cluster.clusterid,self._session_key)
                finally:
                    performance.end_processingstep("get_session_from_other_cluster")
                    pass

                if session:
                    session_data = session["session"]
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
                    try:
                        performance.start_processingstep("get_session_from_other_cluster")
                        if timeout and session_data.get(USER_SESSION_KEY):
                            sessioncache.set(cachekey,session_data,timeout)
                        else:
                            ttl = session.get("ttl")
                            if ttl:
                                sessioncache.set(cachekey,session_data,ttl)
                            else:
                                sessioncache.set(cachekey,session_data,self.get_session_age())
                    finally:
                        performance.end_processingstep("get_session_from_other_cluster")
                        pass
                    return session_data
                else:
                    self._session_key = None
                    return {}

            finally:
                performance.end_processingstep("migrate_session_from_other_cluster")
                pass

