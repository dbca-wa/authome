import logging
import json
import requests
import traceback

from django.conf import settings
from django.utils import timezone
from django.urls import reverse

from ..serializers import JSONDecoder
from .. import utils
from . import cache,get_usercache
from ..exceptions import Auth2ClusterException


logger = logging.getLogger(__name__)

def traffic_monitor(name,func):
    def _monitor(self,request,clusterid,f_send_request):
        start = timezone.localtime()
        res = None
        try:
            res = func(self,request,clusterid,f_send_request)
            status_code = res.status_code
            return res
        except Exception as ex:
            if isinstance(ex,Auth2ClusterException):
                exception = ex.exception
            else:
                exception = ex

            if exception:
                if isinstance(exception,KeyError):
                    status_code = 503
                elif isinstance(exception,requests.Timeout):
                    status_code = 504
                elif isinstance(exception,requests.RequestException):
                    status_code = 503 if exception.response is None else exception.response.status_code
                else:
                    status_code = 503
            else:
                status_code = 503

            logger.debug("Failed to execute '{}',status_code={}.{}".format(name,status_code ,str(ex)))
            raise ex
        finally:
            try:
                self.log_request(name,request.get_host(),start,status_code)
            except:
                logger.error("Failed to log the request.{}".format(traceback.format_exc()))
        
        
    return _monitor if settings.TRAFFIC_MONITOR_LEVEL > 0 else func


class MemoryCache(cache.MemoryCache):
    def __init__(self):
        super().__init__()
        #not includeing the current cluster
        self._auth2_clusters = {}
        self._default_auth2_cluster = None
        self._current_auth2_cluster = None
        self._auth2_clusters_ts = None
        self._auth2_clusters_check_time = cache.IntervalTaskRunable("auth2 clusters cache",settings.AUTH2_CLUSTERS_CHECK_INTERVAL) 

    @property
    def default_auth2_cluster(self):
        """
        In cluster environment, default cluster can be null, but current auth2 cluster can't be null
        """
        if not self._current_auth2_cluster:
            self.refresh_auth2_clusters(True)
        return self._default_auth2_cluster

    @property
    def current_auth2_cluster(self):
        if not self._current_auth2_cluster:
            self.refresh_auth2_clusters(True)
        return self._current_auth2_cluster

    @property
    def auth2_clusters(self):
        if not self._auth2_clusters:
            self.refresh_auth2_clusters(True)
        return self._auth2_clusters

    def refresh_auth2_clusters(self,force=False):
        if self._auth2_clusters_check_time.can_run() or force or not self._auth2_clusters:
            from ..models import Auth2Cluster
            refreshtime = timezone.localtime()
            l1 = len(self._auth2_clusters)
            l2 = 0
            default_auth2_cluster = None
            for o in Auth2Cluster.objects.all():
                o.refreshtime = refreshtime
                if o.default:
                    default_auth2_cluster = o

                if o.clusterid == settings.AUTH2_CLUSTERID:
                    self._current_auth2_cluster = o
                else:
                    self._auth2_clusters[o.clusterid] = o
                    l2 += 1
            self._default_auth2_cluster = default_auth2_cluster
            if l1 != l2 or l1 != len(self._auth2_clusters):
                expired_clusters = [o for o in self._auth2_clusters.values() if o.refreshtime != refreshtime]
                for o in expired_clusters:
                    del self._auth2_clusters[o.clusterid]
            self._auth2_clusters_ts = refreshtime
            return True
        else:
            return False

    def _send_request_to_other_clusters(self,request,f_send_req,force_refresh=False):
        """
        send config changed event to other clusters
        Return the failed clusters with associated exception
        """
        retry_clusters = None
        failed_clusters = None
        changed_clusters = []
        not_changed_clusters = []
        if force_refresh:
            self.refresh_auth2_clusters(True)
        for o in self._auth2_clusters.values():
            try:
                res = f_send_req(o)
                res.raise_for_status()
                if res.status_code == 208:
                    not_changed_clusters.append(o)
                else:
                    changed_clusters.append(o)
            except Exception as ex:
                if not force_refresh and isinstance(ex,(requests.ConnectionError,requests.Timeout)):
                    retry_clusters = utils.add_to_list(retry_clusters,(o,ex))
                else:
                    if isinstance(ex,requests.Timeout):
                        from authome.models import DebugLog
                        DebugLog.warning(DebugLog.INTERCONNECTION_TIMEOUT,None,o.clusterid,None,None,message="Accessing auth2 cluster({1}) times out({0} seconds),{2}".format(settings.AUTH2_INTERCONNECTION_TIMEOUT,o.clusterid,str(ex)),request=request)
                    failed_clusters = utils.add_to_list(failed_clusters,(o,ex))

        if not force_refresh and (retry_clusters or not self._auth2_clusters):
            #some clusters failed
            self.refresh_auth2_clusters(True)
            for o,ex in retry_clusters:
                cluster = self._auth2_clusters.get(o.clusterid)
                if not cluster:
                    continue
                elif o.endpoint == cluster.endpoint:
                    if isinstance(ex,requests.Timeout):
                        from authome.models import DebugLog
                        DebugLog.warning(DebugLog.INTERCONNECTION_TIMEOUT,None,cluster.clusterid,None,None,message="Accessing auth2 cluster({1}) times out({0} seconds),{2}".format(settings.AUTH2_INTERCONNECTION_TIMEOUT,cluster.clusterid,str(ex)),request=request)
                    failed_clusters = utils.add_to_list(failed_clusters,(cluster,ex))
                    continue
                try:
                    res = f_send_req(cluster)
                    res.raise_for_status()
                    if res.status_code == 208:
                        not_changed_clusters.append(cluster)
                    else:
                        changed_clusters.append(cluster)
                except requests.Timeout as ex:
                    from authome.models import DebugLog
                    DebugLog.warning(DebugLog.INTERCONNECTION_TIMEOUT,None,cluster.clusterid,None,None,message="Accessing auth2 cluster({1}) times out({0} seconds),{2}".format(settings.AUTH2_INTERCONNECTION_TIMEOUT,cluster.clusterid,str(ex)),request=request)
                    failed_clusters = utils.add_to_list(failed_clusters,(cluster,ex))
                except Exception as ex:
                    failed_clusters = utils.add_to_list(failed_clusters,(cluster,ex))

        return (changed_clusters,not_changed_clusters,failed_clusters)

    def _send_request_to_cluster(self,request,clusterid,f_send_request):
        """
        send a request to a cluster
        Return the response 
        """
        exception = None
        endpoint = None
        try:
            cluster = self._auth2_clusters[clusterid]
            res = f_send_request(cluster)
            res.raise_for_status()
            return res
        except Exception as ex:
            if isinstance(ex,(KeyError,)):
                exception = ex
            elif isinstance(ex,(requests.ConnectionError,requests.Timeout)):
                exception = ex
                endpoint = self._auth2_clusters[clusterid].endpoint
            else:
                raise Auth2ClusterException("Failed to access cluster({}).{}".format(clusterid,str(ex)),ex)
        
        if self.refresh_auth2_clusters():
            #refreshed
            try:
                if endpoint != self._auth2_clusters[clusterid].endpoint:
                    #endpoint was changed.
                    cluster = self._auth2_clusters[clusterid]
                    res = f_send_request(cluster)
                    res.raise_for_status()
                    return res
                elif isinstance(exception,requests.Timeout):
                    from authome.models import DebugLog
                    DebugLog.warning(DebugLog.INTERCONNECTION_TIMEOUT,None,clusterid,None,None,message="Accessing auth2 cluster({1}) times out({0} seconds),{2}".format(settings.AUTH2_INTERCONNECTION_TIMEOUT,clusterid,str(exception)),request=request)
            except Exception as ex:
                if isinstance(ex,KeyError):
                    raise Auth2ClusterException("Auth2 cluster({}) doesn't exist".format(clusterid),ex)
                elif isinstance(ex,requests.Timeout):
                    from authome.models import DebugLog
                    DebugLog.warning(DebugLog.INTERCONNECTION_TIMEOUT,None,clusterid,None,None,message="Accessing auth2 cluster({1}) times out({0} seconds),{2}".format(settings.AUTH2_INTERCONNECTION_TIMEOUT,clusterid,str(ex)),request=request)
                    exception = ex
                else:
                    exception = ex
        elif isinstance(exception,requests.Timeout):
            from authome.models import DebugLog
            DebugLog.warning(DebugLog.INTERCONNECTION_TIMEOUT,None,clusterid,None,None,message="Accessing auth2 cluster({1}) times out({0} seconds),{2}".format(settings.AUTH2_INTERCONNECTION_TIMEOUT,clusterid,str(exception)),request=request)

        raise Auth2ClusterException("Failed to access cluster({}).{}".format(clusterid,str(exception)),exception)

    def config_changed(self,model_cls,modified=None):
        """
        send config changed event to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            if modified:
                return requests.get("{}{}?modified={}".format(cluster.endpoint,reverse('cluster:config_changed', kwargs={'modelname': model_cls.__name__}),modified.strftime("%Y-%m-%d %H:%M:%S.%f")),headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT,verify=settings.SSL_VERIFY)
            else:
                return requests.get("{}{}".format(cluster.endpoint,reverse('cluster:config_changed', kwargs={'modelname': model_cls.__name__})),headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT,verify=settings.SSL_VERIFY)
        return self._send_request_to_other_clusters(None,_send_request,True)

    def user_changed(self,userid,include_current_cluster=False):
        """
        send user changed event to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(cluster.endpoint,reverse('cluster:user_changed', kwargs={'userid': userid})),headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT,verify=settings.SSL_VERIFY)

        if include_current_cluster:
            local_succeed = True
            try:
                usercache = get_usercache(userid)
                if usercache:
                    usercache.delete(settings.GET_USERTOKEN_KEY(userid))
            except Exception as ex:
                logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))
                local_succeed = False

            result = self._send_request_to_other_clusters(None,_send_request,True)
            if local_succeed:
                result[0].insert(0,self.current_auth2_cluster)
            else:
                result[2].insert(0,self.current_auth2_cluster)
            return result
        else:
            return self._send_request_to_other_clusters(None,_send_request,True)

    def usertoken_changed(self,userid,include_current_cluster=False):
        """
        send user changed event to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(cluster.endpoint,reverse('cluster:usertoken_changed', kwargs={'userid': userid})),headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT,verify=settings.SSL_VERIFY)

        if include_current_cluster:
            local_succeed = True
            try:
                usercache = get_usercache(userid)
                if usercache:
                    usercache.delete(settings.GET_USERTOKEN_KEY(userid))
            except Exception as ex:
                logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))
                local_succeed = False

            result = self._send_request_to_other_clusters(None,_send_request,True)
            if local_succeed:
                result[0].insert(0,self.current_auth2_cluster)
            else:
                result[2].insert(0,self.current_auth2_cluster)
            return result
        else:
            return self._send_request_to_other_clusters(None,_send_request,True)

    def users_changed(self,userids,include_current_cluster=False):
        """
        send user changed events to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            return requests.post("{}{}".format(cluster.endpoint,reverse('cluster:users_changed')),data={"users":userids},headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT)

        if include_current_cluster:
            local_succeed = True
            for userid in userids:
                try:
                    usercache = get_usercache(userid)
                    if usercache:
                        usercache.delete(settings.GET_USER_KEY(userid))
                except Exception as ex:
                    logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))
                    local_succeed = False

            userids = ",".join(userids)
            result = self._send_request_to_other_clusters(None,_send_request,True)
            if local_succeed:
                result[0].insert(0,self.current_auth2_cluster)
            else:
                result[2].insert(0,self.current_auth2_cluster)
            return result
        else:
            userids = ",".join(userids)
            return self._send_request_to_other_clusters(None,_send_request,True)

    def usertokens_changed(self,userids,include_current_cluster=False):
        """
        send user changed events to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            return requests.post("{}{}".format(cluster.endpoint,reverse('cluster:usertokens_changed')),data={"users":userids},headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT)

        if include_current_cluster:
            local_succeed = True
            for userid in userids:
                try:
                    usercache = get_usercache(userid)
                    if usercache:
                        usercache.delete(settings.GET_USERTOKEN_KEY(userid))
                except Exception as ex:
                    logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))
                    local_succeed = False

            userids = ",".join(userids)
            result = self._send_request_to_other_clusters(None,_send_request,True)
            if local_succeed:
                result[0].insert(0,self.current_auth2_cluster)
            else:
                result[2].insert(0,self.current_auth2_cluster)
            return result
        else:
            userids = ",".join(userids)
            return self._send_request_to_other_clusters(None,_send_request,True)

    def _get_headers(self,request=None):
        if request:
            return {
                "HOST":settings.AUTH2_DOMAIN,
                "x-upstream-server-name":request.get_host(),
                "x-upstream-request-uri":request.headers.get("x-upstream-request-uri") or request.get_full_path()
            }
        else:
            return {
                "HOST":settings.AUTH2_DOMAIN
            }

    def get_remote_session(self,clusterid,session,raise_exception=False,request=None):
        """
        get session from other auth2 cluster
        Return the session_data if found; otherwise return None
        """
        target_clusterid = clusterid or (self._default_auth2_cluster.clusterid if self._default_auth2_cluster else None)
        if not target_clusterid:
            # Can't find the auth2 cluster which manage the session
            return None

        def _send_request(cluster):
            return requests.post("{}{}".format(cluster.endpoint,reverse('cluster:get_session')),data={"session":session,"clusterid":clusterid},headers=self._get_headers(request),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT)
        try:
            res = self._get_remote_session(request,target_clusterid,_send_request)
            return json.loads(res.text,cls=JSONDecoder)
        except Auth2ClusterException as ex:
            from ..models import DebugLog
            DebugLog.log(DebugLog.AUTH2_CLUSTER_NOTAVAILABLE,None,target_clusterid,session,utils.get_source_session_cookie(),message="Failed to get remote session({1}) from Auth2 cluster({0}).{2}".format(target_clusterid,session,str(ex)),request=request)
            if raise_exception:
                raise
            else:
                return None
        except Exception as ex:
            from authome.models import DebugLog
            DebugLog.warning(DebugLog.ERROR,None,target_clusterid,session,utils.get_source_session_cookie(),session,message="Failed to get remote session({1}) from Auth2 cluster({0}).{2}".format(target_clusterid,session,str(ex)))
            logger.error("Failed to get session from auth2 cluster '{}'.{}".format(target_clusterid,str(ex)))
            return None

    def delete_remote_session(self,clusterid,session,raise_exception=False,request=None):
        """
        delete remote session from other auth2 cluster
        """
        target_clusterid = clusterid or (self._default_auth2_cluster.clusterid if self._default_auth2_cluster else None)
        if not target_clusterid:
            return

        def _send_request(cluster):
            return requests.post("{}{}".format(cluster.endpoint,reverse('cluster:delete_session')),data={"session":session,"clusterid":clusterid},headers=self._get_headers(request),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT)

        try:
            self._delete_remote_session(request,target_clusterid,_send_request)
        except Auth2ClusterException as ex:
            from ..models import DebugLog
            DebugLog.log(DebugLog.AUTH2_CLUSTER_NOTAVAILABLE,None,target_clusterid,session,utils.get_source_sessioin_cookie(),message="Failed to mark remote session({1}) as migrated from Auth2 cluster({0}).{2}".format(target_clusterid,session,str(ex)),request=request)
            if raise_exception:
                raise
            else:
                return
        except Exception as ex:
            from authome.models import DebugLog
            DebugLog.warning(DebugLog.ERROR,None,target_clusterid,session,utils.get_source_session_cookie(),message="Failed to mark remote session({1}) as migrated from Auth2 cluster({0}).{2}".format(target_clusterid,session,str(ex)))
            logger.error("Failed to mark session as migraed in auth2 cluster '{}'.{}".format(target_clusterid,str(ex)))
            return


    def get_cluster_status(self,clusterid):
        """
        get the status of the cluster server
        Return server status
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(
                cluster.endpoint,
                reverse('cluster:cluster_status')
            ),headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT,verify=settings.SSL_VERIFY)
        try:
            res = self._send_request_to_cluster(None,clusterid,_send_request)
            return res.json()
        except Exception as ex:
            return {
                "clusterid":clusterid,
                "default_cluster":clusterid == self._default_auth2_cluster and self._default_auth2_cluster.clusterid,
                "endpoint":self._auth2_clusters.get(clusterid).endpoint if (clusterid in self._auth2_clusters) else "N/A",
                "healthy":False,
                "errors":str(ex)
            }

    def get_model_cachestatus(self,clusterid):
        """
        get the status of the cluster server
        Return server status
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(
                cluster.endpoint,
                reverse('cluster:model_cachestatus')
            ),headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT,verify=settings.SSL_VERIFY)
        res = self._send_request_to_cluster(None,clusterid,_send_request)
        return res.json()

    def cluster_healthcheck(self,clusterid):
        """
        get the status of the cluster server
        Return server status
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(
                cluster.endpoint,
                reverse('cluster:cluster_healthcheck')
            ),headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT,verify=settings.SSL_VERIFY)
        try:
            res = self._send_request_to_cluster(None,clusterid,_send_request)
            data = res.json()
            return (data["working"],data.get("errors",None))
        except Exception as ex:
            return (False,str(ex))

    def get_auth2_status(self,clusterid):
        """
        get the status of the cluster server
        Return server status
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(
                cluster.endpoint,
                reverse('cluster:auth2_status',kwargs={"clusterid":cluster.clusterid})
            ),headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT,verify=settings.SSL_VERIFY)
        res = self._send_request_to_cluster(None,clusterid,_send_request)
        return res.text

    def get_auth2_liveness(self,clusterid,serviceid,monitordate):
        """
        get the status of the cluster server
        Return server status
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(
                cluster.endpoint,
                reverse('cluster:auth2_liveness',kwargs={"clusterid":cluster.clusterid,"serviceid":serviceid,"monitordate":monitordate})
            ),headers=self._get_headers(),timeout=settings.AUTH2_INTERCONNECTION_TIMEOUT,verify=settings.SSL_VERIFY)
        res = self._send_request_to_cluster(None,clusterid,_send_request)
        return res.text

    @property
    def status(self):
        result = super().status
        result["Auth2Clusters"] = {
            "auth2_clusters":None if self._auth2_clusters else ["{}={}({})".format(o.clusterid,o.endpoint,utils.utils.format_datetime(o.last_heartbeat)) for o in self._auth2_clusters.values()],
            "latest_refresh_time":utils.format_datetime( self._auth2_clusters_ts),
            "next_check_time":utils.format_datetime(self._auth2_clusters_check_time.next_runtime)
        }
        return result

    @property
    def healthy(self):
        health,msgs = super().healthy
        if not self._auth2_clusters and not self._default_auth2_cluster:
            if health:
                health = False
                msgs = ["Auth2 cluster cache is empty"]
            else:
                msgs.append("Auth2 cluster cache is empty")
        
        return (health,msgs)

MemoryCache._get_remote_session = traffic_monitor("get_remote_session",MemoryCache._send_request_to_cluster)
MemoryCache._delete_remote_session = traffic_monitor("delete_remote_session",MemoryCache._send_request_to_cluster)

