import logging
import requests

from django.conf import settings
from django.utils import timezone
from django.urls import reverse

from .. import utils
from . import cache,get_usercache
from ..exceptions import Auth2ClusterException


logger = logging.getLogger(__name__)

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
        if not self._default_auth2_cluster:
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
            for o in Auth2Cluster.objects.all():
                l2 += 1
                o.refreshtime = refreshtime
                if o.default:
                    self._default_auth2_cluster = o

                if o.clusterid == settings.AUTH2_CLUSTERID:
                    self._current_auth2_cluster = o
                else:
                    self._auth2_clusters[o.clusterid] = o
            if l1 != l2 or l1 != len(self._auth2_clusters):
                expired_clusters = [o for o in self._auth2_clusters.values() if o.refreshtime != refreshtime]
                for o in expired_clusters:
                    del self._auth2_clusters[o.clusterid]
            self._auth2_clusters_ts = refreshtime
            return True
        else:
            return False

    def _send_request_to_other_clusters(self,f_send_req):
        """
        send config changed event to other clusters
        Return the failed clusters with associated exception
        """
        retry_clusters = None
        failed_clusters = None
        changed_clusters = []
        not_changed_clusters = []
        for o in self._auth2_clusters.values():
            try:
                res = f_send_req(o)
                res.raise_for_status()
                if res.status_code == 208:
                    not_changed_clusters.append(o)
                else:
                    changed_clusters.append(o)
            except requests.ConnectionError as ex:
                retry_clusters = utils.add_to_list(retry_clusters,(o,ex))
            except requests.HTTPError as ex:
                retry_clusters = utils.add_to_list(retry_clusters,(o,ex))
            except requests.Timeout as ex:
                retry_clusters = utils.add_to_list(retry_clusters,(o,ex))
            except Exception as ex:
                failed_clusters = utils.add_to_list(failed_clusters,(o,ex))
                
        if retry_clusters or not self._auth2_clusters:
            #some clusters failed
            self.refresh_auth2_clusters(True)
            for o,ex in retry_clusters:
                cluster = self._auth2_clusters.get(o.clusterid)
                if not cluster or o.endpoint == cluster.endpoint:
                    failed_clusters = utils.add_to_list(failed_clusters,(cluster,ex))
                    continue
                try:
                    res = f_send_req(cluster)
                    res.raise_for_status()
                    if res.status_code == 208:
                        not_changed_clusters.append(cluster)
                    else:
                        changed_clusters.append(cluster)
                except Exception as ex:
                    failed_clusters = utils.add_to_list(failed_clusters,(cluster,ex))

        return (changed_clusters,not_changed_clusters,failed_clusters)

    def _send_request_to_cluster(self,clusterid,f_send_request):
        """
        send a request to a cluster
        Return the response 
        """
        exception = None
        endpoint = None
        target_clusterid = clusterid or self._default_auth2_cluster.clusterid
        try:
            cluster = self._auth2_clusters[target_clusterid]
            res = f_send_request(cluster)
            res.raise_for_status()
            return res
        except Exception as ex:
            if isinstance(ex,(KeyError,)):
                exception = ex
            elif isinstance(ex,(requests.ConnectionError,requests.HTTPError,requests.Timeout)):
                exception = ex
                endpoint = self._auth2_clusters[target_clusterid].endpoint
            else:
                raise
        
        if self.refresh_auth2_clusters():
            #refreshed
            try:
                if endpoint != self._auth2_clusters[target_clusterid].endpoint:
                    #endpoint was changed.
                    cluster = self._auth2_clusters[target_clusterid]
                    res = f_send_request(cluster)
                    res.raise_for_status()
                    return res
            except Exception as ex:
                if isinstance(ex,(KeyError,requests.ConnectionError,requests.HTTPError,requests.Timeout)):
                    exception = ex
                else:
                    raise
        raise Auth2ClusterException("Failed to access cluster({}).{}".format(target_clusterid,str(exception)))

    def config_changed(self,model_cls,modified=None):
        """
        send config changed event to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            if modified:
                return requests.get("{}{}?modified={}".format(cluster.endpoint,reverse('cluster:config_changed', kwargs={'modelname': model_cls.__name__}),modified.strftime("%Y-%m-%d %H:%M:%S.%f")))
            else:
                return requests.get("{}{}".format(cluster.endpoint,reverse('cluster:config_changed', kwargs={'modelname': model_cls.__name__})))
        return self._send_request_to_other_clusters(_send_request)

    def user_changed(self,userid,include_current_cluster=False):
        """
        send user changed event to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(cluster.endpoint,reverse('cluster:user_changed', kwargs={'userid': userid})))

        if include_current_cluster:
            try:
                usercache = get_usercache(userid)
                if usercache:
                    usercache.delete(settings.GET_USERTOKEN_KEY(userid))
            except Exception as ex:
                logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))

            result = self._send_request_to_other_clusters(_send_request)
            result[0].insert(0,self.current_auth2_cluster)
            return result
        else:
            return self._send_request_to_other_clusters(_send_request)

    def usertoken_changed(self,userid,include_current_cluster=False):
        """
        send user changed event to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(cluster.endpoint,reverse('cluster:usertoken_changed', kwargs={'userid': userid})))

        if include_current_cluster:
            try:
                usercache = get_usercache(userid)
                if usercache:
                    usercache.delete(settings.GET_USERTOKEN_KEY(userid))
            except Exception as ex:
                logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))

            result = self._send_request_to_other_clusters(_send_request)
            result[0].insert(0,self.current_auth2_cluster)
            return result
        else:
            return self._send_request_to_other_clusters(_send_request)

    def users_changed(self,userids,include_current_cluster=False):
        """
        send user changed events to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            return requests.post("{}{}".format(cluster.endpoint,reverse('cluster:users_changed')),data={"users":userids})

        if include_current_cluster:
            for userid in userids:
                try:
                    usercache = get_usercache(userid)
                    if usercache:
                        usercache.delete(settings.GET_USER_KEY(userid))
                except Exception as ex:
                    logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))

            userids = ",".join(userids)
            result = self._send_request_to_other_clusters(_send_request)
            result[0].insert(0,self.current_auth2_cluster)
            return result
        else:
            userids = ",".join(userids)
            return self._send_request_to_other_clusters(_send_request)

    def usertokens_changed(self,userids,include_current_cluster=False):
        """
        send user changed events to other clusters
        Return the failed clusters with associated exception
        """
        def _send_request(cluster):
            return requests.post("{}{}".format(cluster.endpoint,reverse('cluster:usertokens_changed')),data={"users":userids})

        if include_current_cluster:
            for userid in userids:
                try:
                    usercache = get_usercache(userid)
                    if usercache:
                        usercache.delete(settings.GET_USERTOKEN_KEY(userid))
                except Exception as ex:
                    logger.error("Failed to delete the user({}) from user cache.{}".format(userid,str(ex)))

            userids = ",".join(userids)
            result = self._send_request_to_other_clusters(_send_request)
            result[0].insert(0,self.current_auth2_cluster)
            return result
        else:
            userids = ",".join(userids)
            return self._send_request_to_other_clusters(_send_request)


    def get_remote_session(self,clusterid,session,raise_exception=False):
        """
        get session from other auth2 cluster
        Return the session_data if found; otherwise return None
        """
        def _send_request(cluster):
            return requests.post("{}{}".format(cluster.endpoint,reverse('cluster:get_session')),data={"session":session,"clusterid":clusterid})

        try:
            res = self._send_request_to_cluster(clusterid,_send_request)
            return res.json()
        except Auth2ClusterException as ex:
            if raise_exception:
                raise
            else:
                return None
        except Exception as ex:
            logger.error("Failed to get session from auth2 cluster '{}'.{}".format(clusterid,str(ex)))
            return None

    def mark_remote_session_as_migrated(self,clusterid,session,raise_exception=False):
        """
        mark session as migrated in other auth2 cluster
        """
        def _send_request(cluster):
            return requests.post("{}{}".format(cluster.endpoint,reverse('cluster:mark_session_as_migrated')),data={"session":session,"clusterid":clusterid})

        try:
            self._send_request_to_cluster(clusterid,_send_request)
        except Auth2ClusterException as ex:
            logger.error("Failed to mark session as migraed in auth2 cluster '{}'.{}".format(clusterid,str(ex)))
            if raise_exception:
                raise
            else:
                return None
        except Exception as ex:
            logger.error("Failed to mark session as migraed in auth2 cluster '{}'.{}".format(clusterid,str(ex)))
            return None

    def delete_remote_session(self,clusterid,session,raise_exception=False):
        """
        get session from other auth2 cluster
        Return the session_data if found; otherwise return None
        """
        def _send_request(cluster):
            requests.post("{}{}".format(cluster.endpoint,reverse('cluster:delete_session')),data={"session":session,"clusterid":clusterid})

        try:
            self._send_request_to_cluster(clusterid,_send_request)
        except Auth2ClusterException as ex:
            if raise_exception:
                raise
            else:
                return None
        except Exception as ex:
            logger.error("Failed to delete session from {}.{}".format(clusterid,str(ex)))
            return None

    def get_traffic_data(self,clusterid,level,starttime,endtime):
        """
        get traffic from other auth2 cluster
        Return traffic data; if failed, return None
        """
        def _send_request(cluster):
            return requests.get("{}{}?level={}&starttime={}&endtime={}".format(
                cluster.endpoint,
                reverse('cluster:cluster_traffic_data'),
                level,
                starttime.strftime("%Y-%m-%d %H:%M:%S"),
                endtime.strftime("%Y-%m-%d %H:%M:%S")
            ))

        res = self._send_request_to_cluster(clusterid,_send_request)
        return res.json()

    def get_cluster_status(self,clusterid):
        """
        get the status of the cluster server
        Return server status
        """
        def _send_request(cluster):
            return requests.get("{}{}".format(
                cluster.endpoint,
                reverse('cluster:cluster_status')
            ))
        try:
            res = self._send_request_to_cluster(clusterid,_send_request)
            return res.json()
        except Exception as ex:
            return {
                "clusterid":clusterid,
                "default_cluster":clusterid == self._default_auth2_cluster and self._default_auth2_cluster.clusterid,
                "endpoint":self._auth2_clusters.get(clusterid).endpoint if (clusterid in self._auth2_clusters) else "N/A",
                "healthy":False,
                "errors":[str(ex)]
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
            ))
        res = self._send_request_to_cluster(clusterid,_send_request)
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
            ))
        try:
            res = self._send_request_to_cluster(clusterid,_send_request)
            data = res.json()
            return (data["healthy"],data.get("errors","OK"))
        except Exception as ex:
            return (False,[str(ex)])

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
        if not self._auth2_clusters:
            if health:
                health = False
                msgs = ["Auth2 cluster cache is empty"]
            else:
                msgs.append("Auth2 cluster cache is empty")
        
        return (health,msgs)

