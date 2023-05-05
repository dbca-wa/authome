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
from authome.models import DebugLog

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
    _clusterid_prefix = settings.AUTH2_CLUSTERID.replace("-","").replace("_","").lower() if settings.AUTH2_CLUSTERID else ""
    def __init__(self,lb_hash_key,auth2_clusterid,session_key,request=None,cookie_domain=None):
        super().__init__(session_key=session_key,request=request,cookie_domain=cookie_domain)
        self._lb_hash_key = lb_hash_key
        self._source_auth2_clusterid = auth2_clusterid

    @property
    def _signature(self):
        return utils.sign_session_cookie(self._lb_hash_key,settings.AUTH2_CLUSTERID,(self._session_key or self.expired_session_key),settings.SECRET_KEY)

    @property
    def cookie_changed(self):
        return self._cookie_changed or self._source_session_key != (self._session_key or self.expired_session_key) or self._source_auth2_clusterid != settings.AUTH2_CLUSTERID


    @property
    def source_session_key(self):
        return utils.get_source_session_key(self._request)

    @property
    def source_session_cookie(self):
        return utils.get_source_session_cookie(self._request)

    def get_session_cookie_age(self,session_cookie=None):
        """
        Return different session cookie age for authenticated session and anonymous session
        """
        if session_cookie:
            session_key = session_cookie.rsplit("|",1)[-1]
        else:
            session_key = self._session_key
        if session_key and "-" in session_key:
            return settings.SESSION_COOKIE_AGE
        else:
            return settings.GUEST_SESSION_AGE

    def populate_session_key(self,process_prefix,idpid):
        if idpid:
            return "{4}-{0}{2}{1}{3}".format(
                self._clusterid_prefix,
                process_prefix,
                get_random_string(16, sessionstore.VALID_KEY_CHARS),
                get_random_string(16, sessionstore.VALID_KEY_CHARS),
                idpid
            )
        else:
            return "{0}{2}{1}{3}".format(
                self._clusterid_prefix,
                process_prefix,
                get_random_string(16, sessionstore.VALID_KEY_CHARS),
                get_random_string(16, sessionstore.VALID_KEY_CHARS)
            )

        
    @property
    def cookie_value(self):
        #should be only called if session is not empty
        if self._cookie_domain:
            return "{}|{}|{}|{}{}{}".format(self._lb_hash_key,settings.AUTH2_CLUSTERID,self._signature,self.session_key or self.expired_session_key,settings.SESSION_COOKIE_DOMAIN_SEPATATOR,self._cookie_domain)
        else:
            return "{}|{}|{}|{}".format(self._lb_hash_key,settings.AUTH2_CLUSTERID,self._signature,self.session_key or self.expired_session_key)

    def load(self):
        if self._source_auth2_clusterid == settings.AUTH2_CLUSTERID:
            #local cluster session 
            return super().load()
        session_data = None
        if not self._source_auth2_clusterid and auth2cache.current_auth2_cluster.default:
            #sessionid created in the same auth2 server,
            #upgrade the session to cluster session
            if settings.STANDALONE_CACHE_KEY_PREFIX == settings.CACHE_KEY_PREFIX:
                #cache key prefix is not changed, cluster session key is the same as the non-cluster session key
                session_data = super().load()
                DebugLog.log_if_true(session_data,DebugLog.UPGRADE_SESSION,self._lb_hash_key,None,self._session_key,self.source_session_cookie,message="Upgrade a session({}) from the same server to cluster session({})".format(self.source_session_cookie,self.cookie_value),target_session_cookie=self.cookie_value,userid=(session_data or {}).get(USER_SESSION_KEY),request=self._request)

                DebugLog.log_if_true(not session_data,DebugLog.UPGRADE_NONEXIST_SESSION,self._lb_hash_key,None,self._session_key,self.source_session_cookie,message="No need to upgrade a non-existing session({}) from the same server to cluster session".format(self.source_session_cookie),request=self._request)
                return session_data
            else:
                try:
                    performance.start_processingstep("upgrade_to_cluster_session")
                    standalone_sessionstore = StandaloneSessionStore(session_key=self._session_key,request=self._request)
                    try:
                        performance.start_processingstep("load_noncluster_session_from_same_cluster")
                        session_data = standalone_sessionstore.load()
                    finally:
                        performance.end_processingstep("load_noncluster_session_from_same_cluster")
                        pass

                    newcachekey = self.cache_key
                    sessioncache = self._get_cache()
                    if session_data:
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
                                performance.start_processingstep("get_noncluster_session_ttl_from_same_cluster")
                                ttl = standalone_sessionstore.ttl
                            except:
                                ttl = None
                            finally:
                                performance.end_processingstep("get_noncluster_session_ttl_from_same_cluster")
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
                            performance.start_processingstep("delete_noncluster_session")
                            standalone_sessionstore.delete()
                        finally:
                            performance.end_processingstep("delete-noncluster_session")
                            pass
                        DebugLog.log(DebugLog.UPGRADE_SESSION,self._lb_hash_key,None,self._session_key,self.source_session_cookie,message="Upgrade a session({}) from the same server to cluster session({})".format(self.source_session_cookie,self.cookie_value),target_session_cookie=self.cookie_value,userid=session_data.get(USER_SESSION_KEY),request=self._request)
                    else:
                        try:
                            performance.start_processingstep("load_cluster_session_from_same_cluster")
                            session_data = sessioncache.get(newcachekey)
                            DebugLog.log_if_true(session_data,DebugLog.SESSION_ALREADY_UPGRADED,self._lb_hash_key,None,self._session_key,self.source_session_cookie,message="The session({0}) has already upgraded from the same server to cluster session({1})".format(self.source_session_cookie,self.cookie_value),target_session_cookie=self.cookie_value,userid=(session_data or {}).get(USER_SESSION_KEY),request=self._request)
                            DebugLog.log_if_true(not session_data,DebugLog.UPGRADE_NONEXIST_SESSION,self._lb_hash_key,None,self._session_key,self.source_session_cookie,message="No need to upgrade a non-existing session({}) from the same server to cluster session".format(self.source_session_cookie),request=self._request)
                        finally:
                            performance.end_processingstep("load_cluster_session_from_same_cluster")
                            pass
    
                    if session_data :
                        return session_data
        
                    #expired authenticated session, or session does not exist
                    if self._session_key and "-" in self._session_key and self.samedomain:
                        #keep the session cookie to sign out from B2C if the session is authenticated session and also come from the same domain; otherwise, delete the session cookie from browser to let user signin again, if b2c cookie still exists in the browser, the user will automatically sign in 
                        self.expired_session_key = self._session_key
                    self._session_key = None
                    return {}
                except :
                    logger.error("Failed to load session.{}".format(traceback.format_exc()))
                    DebugLog.warning(DebugLog.ERROR,self._lb_hash_key,None,self._session_key,utils.get_source_session_cookie(self._request),message="Failed to upgrade a session({}) from the same server to cluster session.{}".format(utils.get_source_session_cookie(self._request),traceback.format_exc()),request=self._request)
                    self._session_key = None
                    return {}
                finally:
                    performance.end_processingstep("upgrade_to_cluster_session")
                    pass
        elif self._source_auth2_clusterid or auth2cache.default_auth2_cluster:
            #session should be migrated from original server to current server
            try:
                performance.start_processingstep("migrate_session_from_other_cluster")
                try:
                    performance.start_processingstep("load_session_from_other_cluster")
                    session = auth2cache.get_remote_session(self._source_auth2_clusterid,self._session_key,False,request=self._request)
                finally:
                    performance.end_processingstep("load_session_from_other_cluster")
                    pass

                cachekey = self.cache_key
                sessioncache = self._get_cache()

                if session:
                    session_data = session["session"]
                    timeout = session_data.get("session_timeout")
                    try:
                        performance.start_processingstep("set_cluster_session_to_cache")
                        if timeout and session_data.get(USER_SESSION_KEY):
                            sessioncache.set(cachekey,session_data,timeout)
                        else:
                            ttl = session.get("ttl")
                            if ttl:
                                sessioncache.set(cachekey,session_data,ttl)
                            else:
                                sessioncache.set(cachekey,session_data,self.get_session_age())
                    finally:
                        performance.end_processingstep("set_cluster_session_to_cache")
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
                        performance.start_processingstep("delete_remote_session")
                        auth2cache.delete_remote_session(self._source_auth2_clusterid ,self._session_key,False,request=self._request)
                    finally:
                        performance.end_processingstep("delete_remote_session")
                        pass
                    DebugLog.log(DebugLog.MIGRATE_SESSION if self._source_auth2_clusterid else DebugLog.UPGRADE_SESSION,self._lb_hash_key,self._source_auth2_clusterid,self.source_session_key,self.source_session_cookie,message="{} a session({}) from {} to cluster session({})".format("Migrate" if self._source_auth2_clusterid else  "Upgrade",self.source_session_cookie,self._source_auth2_clusterid or auth2cache.default_auth2_cluster.clusterid,self.cookie_value),target_session_cookie=self.cookie_value,userid=session_data.get(USER_SESSION_KEY),request=self._request)
                else:
                    try:
                        performance.start_processingstep("load_cluster_session_from_same_cluster")
                        session_data = sessioncache.get(cachekey)

                        DebugLog.log_if_true(session_data,DebugLog.SESSION_ALREADY_MIGRATED if self._source_auth2_clusterid else DebugLog.SESSION_ALREADY_UPGRADED,self._lb_hash_key,self._source_auth2_clusterid,self.source_session_key,self.source_session_cookie,message="The session({}) has already {} from {} to cluster session({})".format(self.source_session_cookie,"migrated" if self._source_auth2_clusterid else  "upgraded",self._source_auth2_clusterid or auth2cache.default_auth2_cluster.clusterid,self.cookie_value),target_session_cookie=self.cookie_value,userid=(session_data or {}).get(USER_SESSION_KEY),request=self._request)

                        DebugLog.log_if_true(not session_data,DebugLog.MIGRATE_NONEXIST_SESSION if self._source_auth2_clusterid else DebugLog.UPGRADE_NONEXIST_SESSION,self._lb_hash_key,self._source_auth2_clusterid,self.source_session_key,self.source_session_cookie,message="No need to {} a non-existing session({}) from {} to cluster({})".format("migrate" if self._source_auth2_clusterid else  "upgrade",self.source_session_cookie,self._source_auth2_clusterid or auth2cache.default_auth2_cluster.clusterid,auth2cache.current_auth2_cluster.clusterid),request=self._request)
                    finally:
                        performance.end_processingstep("load_cluster_session_from_same_cluster")
                        pass

                if session_data :
                    return session_data
    
                self._session_key = None
                return {}
            except :
                logger.error("Failed to load session.{}".format(traceback.format_exc()))
                DebugLog.warning(DebugLog.ERROR,self._lb_hash_key,self._source_auth2_clusterid,self.source_session_key,self.source_session_cookie,message="Failed to {} a non-existing session({}) from {} to cluster session.{}".format("migrate" if self._source_auth2_clusterid else  "upgrade",self.source_session_cookie,self._source_auth2_clusterid or auth2cache.default_auth2_cluster.clusterid,traceback.format_exc()),request=self._request)
                self._session_key = None
                return {}
            finally:
                performance.end_processingstep("migrate_session_from_other_cluster")
                pass

        else:
            DebugLog.log(DebugLog.UPGRADE_NONEXIST_SESSION,self._lb_hash_key,self._source_auth2_clusterid,self.source_session_key,self.source_session_cookie,message="Can't upgrade a session({}) to cluster({}) without default auth2 cluster".format(self.source_session_cookie,auth2cache.current_auth2_cluster.clusterid),request=self._request)
            self._session_key = None
            return {}


