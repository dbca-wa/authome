import traceback
from datetime import timedelta
import json
import time
from itertools import chain
import redis
from redis.cluster import PRIMARY,REPLICA
from redis.exceptions import ConnectionError,TimeoutError,ClusterError,RedisClusterException,ClusterDownError
from collections import OrderedDict
import logging

from django.conf import settings
from django.core.cache.backends import redis as django_redis
from django.utils import timezone
from django.utils.functional import cached_property

from .. import utils
from ..serializers import Processtime
from .base import CacheMixin,redis_re

logger = logging.getLogger(__name__)

class RedisClusterMixin(object):
    """
    Provide some common data structure and features for redis cluster
    _groups: a list of cluster group which is a list of groupnode name(host:port)
    _groupmap: a dict between groupnode name(host:port) and cluster group

    """
    _groups = None
    _groupmap = None

    def __init__(self,*args,**kwargs):
        groups = kwargs.pop("groups",None)
        self.init_groups(groups)
        super().__init__(*args,**kwargs)
 
    @property
    def dynamic_startup_nodes(self):
        return self.nodes_manager._dynamic_startup_nodes

    def init_groups(self,groups):
        """
        Init the redis cluster groups from the cluster configuration 'groups' in cluster option.
        groups: a string, cluster group are separated by '|', group node are separated by ';'
        """
        if not groups:
            raise Exception("Please configure redis cluster groups in redis server options.")

        succeed = True
        self._groupmap = {}
        self._groups = [[node for node in group.strip().split(";") if node and node.strip()] for group in groups.split("|") if group and group.strip()]
        for group in self._groups:
            group.sort()

        for group in self._groups:
            for groupnode in group:
                self._groupmap[groupnode] = group

    @property
    def clustergroups(self):
        """
        Return the list of cluster groups
        """
        return self._groups

    def get_clustergroup(self,nodename):
        """
        nodename: host:port
        Return the cluster group to which the nodename belongs
        """
        return self._groupmap.get(nodename)

class RedisCluster(RedisClusterMixin,redis.RedisCluster):
    """
    A traditional redis cluster client from redis library
    """
    pass
            
class AutoFailoverRedisCluster(RedisClusterMixin,redis.RedisCluster):
    """
    A redis cluster which can automatically trigger a master switch if the current master is not available.
    This class only supports fixed redis cluster that means redis cluster can't shrink and extend during running.
    """

    def masternode_failover(self,nodename=None,masternode=None):
        """
        Perform a manual master node failover, only used when the current master node is offline
        Raise exception if failed
        Return new master node object
        """
        #try to find the node from node_manager
        if not nodename:
            nodename = masternode.name
        else:
            masternode = self.get_or_create_node(nodename)
        clustergroup = self.get_clustergroup(nodename)

        #start the manual failover
        try:
            resp = super()._execute_command(masternode,"CLUSTER FAILOVER","TAKEOVER")
        except redis.ResponseError as ex:
            if "You should send CLUSTER FAILOVER to a replica" in str(ex):
                #already switched
                logger.debug("{}: The node({}) was already switched to master node".format(utils.get_processid(), nodename))
                self.init_nodesmanager_with_masternode(nodename)
                return masternode
            else:
                logger.warning("{}: Failed to switch the node({}) to master node.{}".format(utils.get_processid(),nodename,ex))
                raise ex

        #check whether the switch operation is completed.
        try_time = 0
        while try_time < settings.REDISCLUSTER_FAILOVER_CHECK_TIMES:
            clusternodes = super()._execute_command(masternode,"CLUSTER NODES")
            if "master" in clusternodes[nodename]["flags"] and "fail" not in clusternodes[nodename]["flags"] and clusternodes[nodename]["connected"]:
                #switched successfully
                logger.debug("{}: Succeed to switch the node({}) to master node.".format(utils.get_processid(),nodename))
                self.init_nodesmanager_with_masternode(nodename)
                return masternode
            else:
                for groupnode in clustergroup:
                    if "master" in clusternodes[groupnode]["flags"] and "fail" not in clusternodes[groupnode]["flags"] and clusternodes[groupnode]["connected"]:
                        #another node was chosen by redis cluster as master node
                        logger.debug("{}: Try to switch the node({}) to master node, but the node({}) was chosen by redis as master node".format(utils.get_processid(), nodename,groupnode))
                        self.init_nodesmanager_with_masternode(groupnode)
                        return self.get_or_create_node(groupnode)
            try_time += 1
            if try_time < 10:
                time.sleep(settings.REDISCLUSTER_FAILOVER_CHECK_INTERVAL)

        raise Exception("{}: Failed to switch the node({}) to master node without exception".format(utils.get_processid(),nodename))

    def find_another_default_node(self):
        """
        Try to find another default node to replace the current default node which should be unavailable
        1. Try primary nodes
        2. Try replica nodes
        3. Try nodes which are not returned in the redis cluster server
        Return a node object if succeed
        """
        #get the current default node
        curr_node = self.get_default_node()
        tried_nodes = set()
        #add to the tried_ndoes, because it should be not available now.
        tried_nodes.add(curr_node.name)
        #try to find a default node from primary nodes and then replica nodes
        for node in chain(self.get_primaries(),self.get_replicas()):
            if node.name in tried_nodes:
                continue
            tried_nodes.add(node.name)
            try:
                if super()._execute_command(node,"PING"):
                    #Found a available node, it can be primary node or replica node. 
                    return node
            except:
                continue

        #can't find a node from nodes_manager, try to find a accessible node from all nodes of the redis cluster.
        for group in self._groups:
            for groupnode in group:
                if groupnode in tried_nodes:
                    continue
                #find the host and port from group node
                if ":" in groupnode:
                    host,port = groupnode.split(":")
                    port = int(port)
                else:
                    host = groupnode
                    port = 6379
                    
                node = self.nodes_manager._get_or_create_cluster_node(host, port,REPLICA,self.nodes_manager.nodes_cache)
                self.nodes_manager.create_redis_connections([node])
                try:
                    if super()._execute_command(node,"PING"):
                        #the node is accessible
                        return self.masternode_failover(masternode=node)
                except:
                    #failed, try another one
                    continue
        raise Exception("Failed to find an alternative redis server to be the default redis server.")

    def get_cluster_nodes(self,failed_node=None):
        """
        Return cluster nodes from redis cluster server
        1. Try primary nodes.
        2. Try repllica nodes
        3. Try other nodes which belongs to redis cluster but currently not recoginzed by nodes manager
        """
        ex =  None
        tried_nodes = set()
        if failed_node:
            tried_nodes.add(failed_node)

        #Try to get the cluster nodes from primaries and then replicas
        for attempt in range(2):
            for group in self._groups:
                for groupnode in group:
                    if  groupnode in tried_nodes:
                        #already tried, 
                        continue
                    node = self.nodes_manager.get_node(node_name=groupnode)
                    if not node:
                        continue
                    if node.server_type != (PRIMARY if attempt == 0 else REPLICA): 
                        #filter out the not-matched nodes.
                        #first attempt: try primary nodes
                        #second attempt : try replica nodes
                        continue

                    tried_nodes.add(groupnode)
                    if not node.redis_connection:
                        continue
                    try:
                        return super()._execute_command(node,"CLUSTER NODES")
                    except Exception as e:
                        continue
        #Failed to get the cluster nodes from primaries and replicas
        #Try to get cluster nodes from nodes not recognzied by node manager

        #Found the oldest node
        chosen_node = None
        uptime = -1
        for group in self._groups:
            for groupnode in group:
                if  groupnode in tried_nodes:
                    continue
                if ":" in groupnode:
                    host,port = groupnode.split(":")
                    port = int(port)
                else:
                    host = groupnode
                    port = 6379
                        
                node = self.nodes_manager._get_or_create_cluster_node(host, port,PRIMARY,{})
                self.nodes_manager.create_redis_connections([node])

                try:
                    seconds = super()._execute_command(node,"info","server").get("uptime_in_seconds",0)
                    if uptime < seconds:
                        uptime = seconds
                        chosen_node = node
                except Exception as e:
                    ex = e

        #if found the oldest node, try to get the cluster nodes from the chosen node
        if chosen_node:
            #Found the oldest node, get the cluster nodes
            try:
                return super()._execute_command(chosen_node,"CLUSTER NODES")
            except Exception as e:
                ex = e

        raise ex

    def init_nodesmanager_with_masternode(self,nodename):
        """
        nodename: the node name of the new master node. host:port
        Reinitialize the nodes manager with the new master node
        """
 
        added = False
        if not isinstance(self.nodes_manager.startup_nodes,OrderedDict):
            startup_nodes = OrderedDict(self.nodes_manager.startup_nodes)
            self.nodes_manager.startup_nodes = startup_nodes

        if nodename not in self.nodes_manager.startup_nodes:
            masternode = self.get_or_create_node(nodename)
            self.nodes_manager.startup_nodes[nodename] = masternode
            added = True

        #move the new master node to the first position.
        self.nodes_manager.startup_nodes.move_to_end(nodename,last=False)

        #reinitialzie the node manager with the new master node
        self.nodes_manager.initialize()

        #restore the startup_nodes if dynamic_startup_nodes is False
        if added and not self.dynamic_startup_nodes:
            #the nodename node was newly added to startup_nodes and dynamic_startup_nodes is False, remove the nodename from startup_nodes
            self.nodes_manager.startup_nodes.pop(nodename,None)

    def get_or_create_node(self,nodename,nodetype=PRIMARY):
        """
        Return the redis node based on nodename(host:port), create it if it doesn't exist before
        """
        node = self.nodes_manager.get_node(node_name = nodename)
        if not node:
            #can't find the node from node_manager, maybe majority of redis master are down, try to create a node manually
            if ":" in nodename:
                host,port = nodename.split(":")
                port = int(port)
            else:
                host = nodename
                port = 6379
                            
            node = self.nodes_manager._get_or_create_cluster_node(host, port,nodetype,self.nodes_manager.nodes_cache)
            self.nodes_manager.create_redis_connections([node])
        return node

        
    def switch_masternode(self,failed_node=None,host=None,port=None,prefered_master=None,node=None):
        """
        switch the master node in that group to which the node belongs
        failed_node: a crashed node, can be node name or node object
        host: the host of the crashed node
        portL the port of the crashed port
        prefered_master: the prefered master node, can be node name or node object
        node: a node used to find the cluster group, can be node name or node object
        Return the new master node if switch succeed; otherwise return None
        """
        new_master = None
        
        #locate the failed node via host and port
        if  failed_node:
            if not isinstance(failed_node,str):
                failed_node = failed_node.name
        elif host:
            failed_node = "{}:{}".format(host,port or 6379)

        if prefered_master and not isinstance(prefered_master,str):
            prefered_master = prefered_master.name
            
        if node and not isinstance(node,str):
            node = node.name
            
        group = self._groupmap.get(failed_node or prefered_master or node)
        if not group:
            raise Exception("Can't find the redis group for the node({})".format(failed_node or prefered_master or node))

        nodes = self.get_cluster_nodes(failed_node)

        tried_nodes = set()
        if failed_node:
            tried_nodes.add(failed_node)

        for attempt in range(5):
            if len(group) == len(tried_nodes):
                break
            elif attempt == 1:
                #second round, try the prefered master
                if not prefered_master:
                    #no prefered master, ignore the second round
                     continue

            for groupnode in group:
                if groupnode in tried_nodes:
                    continue

                if attempt == 0:
                    #first round, try the current master node first
                    if groupnode not in nodes:
                        continue
                    if "master" not in nodes[groupnode]["flags"] or "fail" in nodes[groupnode]["flags"] :
                        continue
                elif attempt == 1:
                    #second round, try the prefered master
                    if groupnode != prefered_master:
                        continue
                elif attempt == 2:
                    #third round, try the non-failed nodes
                    if groupnode not in nodes:
                        continue
                    if "fail" in nodes[groupnode]["flags"]:
                        continue
                elif attempt == 3:
                    #fourth round, try the failed nodes
                    if groupnode not in nodes:
                        continue
                    if "fail" not in nodes[groupnode]["flags"]:
                        #already processed in the first round
                        continue
                else:
                     #fifth round, try the nodes which are not returned from cluster nodes
                     if groupnode in nodes:
                        continue
                try:
                    #try to find the node from node_manager
                    tried_nodes.add(groupnode)
                    return self.masternode_failover(nodename=groupnode)
                except Exception as ex:
                    continue
        if failed_node:
            raise Exception("{}: Failed to find an alternative redis server to replace the current master({})".format(utils.get_processid(),failed_node))
        else:
            raise Exception("{}: Failed to find an alternative redis server to be the new master node".format(utils.get_processid()))

    def _execute_command(self, target_node, *args, **kwargs):
        """
        Send a command to a node in the cluster
        """
        try:
            return super()._execute_command(target_node,*args,**kwargs)
        except (ConnectionError,TimeoutError) as ex:
            if target_node.server_type == PRIMARY:
                #treat target_node as normal node instead of failed_node because the failed operation maybe be caused by broken connection instead of crashed redis.
                #Treat the target_node as normal node can give the target_node another chance.
                new_masternode = self.switch_masternode(node=target_node)
                if target_node == self.get_default_node():
                    #this is the default node
                    self.replace_default_node(new_masternode)
                return super()._execute_command(new_masternode,*args,**kwargs)
            elif target_node == self.get_default_node():
                new_defaultnode = self.find_another_default_node()
                self.replace_default_node(new_defaultnode)
                return super()._execute_command(new_defaultnode,*args,**kwargs)
            raise ex
        except ClusterDownError as ex:
            if target_node.server_type == PRIMARY:
                new_masternode = self.switch_masternode(prefered_master=target_node)
                if target_node == self.get_default_node():
                    #this is the default node
                    self.replace_default_node(new_masternode)
                return super()._execute_command(new_masternode,*args,**kwargs)
            elif target_node == self.get_default_node():
                new_defaultnode = self.find_another_default_node()
                self.replace_default_node(new_defaultnode)
                return super()._execute_command(new_defaultnode,*args,**kwargs)
            raise ex
        except Exception as ex:
            raise

class RedisClusterCacheClient(django_redis.RedisCacheClient):
    """
    A django cache client for redis cluster

    """
    _redisclient = None
    def __init__(self, *args,auto_failover=False,**kwargs):
        super().__init__(*args,**kwargs)
        if auto_failover:
            logger.debug("Redis cluster master auto failover feature is enabled. ")
            self._client = AutoFailoverRedisCluster
        else:
            self._client = RedisCluster
        
    def ttl(self, key):
        client = self.get_client(key)
        return client.ttl(key)

    def expire(self, key,timeout):
        client = self.get_client(key, write=True)
        return client.expire(key,timeout)

    def get_client(self, key=None, *, write=False):
        """
        Return a cached redis client to access redis cluster data
        """
        # key is used so that the method signature remains the same and custom
        # cache client can be implemented which might require the key to select
        # the server, e.g. sharding.
        if not self._redisclient:
            #redis client is not initialized.
            if isinstance(self._servers,list):
                startup_nodes = []
                for server in self._servers[:-1]:
                    m = redis_re.search(server)
                    if not m:
                        raise Exception("Invalid redis server '{}'".format(server))
                    startup_nodes.append(redis.cluster.ClusterNode(m.group('host'),m.group('port') or 6379))
                self._redisclient = self._client(startup_nodes = startup_nodes , url = self._servers[-1] , **self._pool_options)
            else:
                self._redisclient = self._client.from_url(self._servers,**self._pool_options)

        return self._redisclient

class RedisClusterCache(CacheMixin,django_redis.RedisCache):
    """
    A django cache for redis cluster
    """

    def __init__(self, server, params):
        if self.cacheid:
            #already initialized.
            return
        self.cacheid = params.pop("CACHEID")
        self._server_clients = None
        self._cluster_nodes_data = None
        self._failed_cluster_nodes = []
        server = server.strip(" ;")
        super().__init__(server,params)
        self._class = RedisClusterCacheClient

    @cached_property
    def redis_client(self):
        """
        A redis client to access redis cluster
        """
        return self._cache.get_client()

    def get_serverinfo(self,data):
        role = data.get("role")
        if not role:
            return "system_memory = {} , used_memory = {} , keys = {} , starttime = {} , redis_version = {}".format(
                data.get("total_system_memory_human","N/A"),
                data.get("used_memory_human","N/A"),
                data.get("db{}".format(self.db),{}).get("keys","0") if self.db >= 0 else "N/A",
                utils.format_datetime(timezone.localtime() - timedelta(seconds=data.get("uptime_in_seconds"))) if "uptime_in_seconds" in data else "N/A",
                data.get("redis_version","N/A"),
            )
        elif role == "master":
            return "system_memory = {} , used_memory = {} , role = master , keys = {} , starttime = {} , redis_version = {}".format(
                data.get("total_system_memory_human","N/A"),
                data.get("used_memory_human","N/A"),
                data.get("db{}".format(self.db),{}).get("keys","0") if self.db >= 0 else "N/A",
                utils.format_datetime(timezone.localtime() - timedelta(seconds=data.get("uptime_in_seconds"))) if "uptime_in_seconds" in data else "N/A",
                data.get("redis_version","N/A"),
            )
        else:
            return "system_memory = {} , used_memory = {} , role = slave , keys = {} , starttime = {} , redis_version = {} , master = {}".format(
                data.get("total_system_memory_human","N/A"),
                data.get("used_memory_human","N/A"),
                data.get("db{}".format(self.db),{}).get("keys","0") if self.db >= 0 else "N/A",
                utils.format_datetime(timezone.localtime() - timedelta(seconds=data.get("uptime_in_seconds"))) if "uptime_in_seconds" in data else "N/A",
                data.get("redis_version","N/A"),
                "{}:{}".format(data.get("master_host"),data.get("master_port"))
            )

    def ping(self):
        """
        This method will update the data _failed_cluster_nodes if necessary
        Ping each redis server belonging the redis cluster.
        Return the health status of the redis cluster
        """
        from ..cache import cache

        redisclients = self._redis_server_clients
        starttime = None
        pingstatus = {}
        for redisclient in redisclients:
            starttime = timezone.localtime()
            status = self.ping_redis(redisclient)
            pingstatus[redisclient[0]] = {"ping":status[0],"pingtime":Processtime((timezone.localtime() - starttime).total_seconds())}
            if status[0]:
                #redis server is online, remove the server from _failed_cluster_nodes 
                try:
                    i =  self._failed_cluster_nodes.index(redisclient[0])
                    del self._failed_cluster_nodes[i]
                except ValueError as ex:
                    pass
            else:
                #redis server is offline, Add this server into _failed_cluster_nodes
                if redisclient[0] not in self._failed_cluster_nodes:
                    self._failed_cluster_nodes.append(redisclient[0])
                if status[1]:
                    pingstatus[redisclient[0]]["error"] = status[1]

        if not self._failed_cluster_nodes:
            return (True,pingstatus)

        offline_groups = []
        partially_failed_groups = []

        for group in self.redis_client._groups:
            if all(groupnode in self._failed_cluster_nodes for groupnode in group):
                offline_groups.append(group)
            else:
                nodes = [groupnode for groupnode in group if groupnode in self._failed_cluster_nodes]
                if nodes:
                    partially_failed_groups.append((group,nodes))

        if not offline_groups and not partially_failed_groups:
            return (True,pingstatus)
        elif len(offline_groups) == len(self.redis_client._groups):
            pingstatus["error"] = "The redis cluster is offline"
            return (False,pingstatus)
        else:
            errors = None
            for group in offline_groups:
                errors = utils.add_to_list(errors,"The redis cluster group({}) is offline.".format(group))
            for group,failed_nodes in partially_failed_groups:
                if len(failed_nodes) == 1:
                    errors = utils.add_to_list(errors,"The node({1}) in redis cluster group({0}) is offline.".format(group,failed_nodes[0]))
                else:
                    errors = utils.add_to_list(errors,"The nodes({1}) in redis cluster group({0}) are offline.".format(group,failed_nodes))
            
            pingstatus["errors"] = errors

            return (False if offline_groups else True,pingstatus)

    def _get_server_status(self,redisclient):
        """
        This method will update the data _failed_cluster_nodes if necessary
        Get the server info
        """
        result = super()._get_server_status(redisclient)
        if result[0]:
            #redis server is online, remove the server from _failed_cluster_nodes 
            try:
                i =  self._failed_cluster_nodes.index(redisclient[0])
                del self._failed_cluster_nodes[i]
            except ValueError as ex:
                pass
        else:
            #redis server is offline, Add this server into _failed_cluster_nodes
            if redisclient[0] not in self._failed_cluster_nodes:
                self._failed_cluster_nodes.append(redisclient[0])
        return result

    @property   
    def _redis_server_clients(self):
        """
        This operation will re_get_server_statuspopulate the data _failed_cluster_nodes
        Return a list of [nodename(host:port), a redis client to access the redis server]
        """
        redisclient = self.redis_client

        refresh = False
        if not self._server_clients:
            #not init before, set the cluster nodes data
            self._cluster_nodes_data = self.redis_client.get_cluster_nodes()
            refresh = True
        elif any(not client[1] for client in self._server_clients):
            #some nodes are offline
            refresh = True

        if refresh:
            #cached server_clients doesn't match with the nodes_cache
            cluster_nodes_data = self.redis_client.get_cluster_nodes()
            if self._cluster_nodes_data != cluster_nodes_data:
                #cluster nodes data was changed, reinitialize nodes manager
                redisclient.nodes_manager.initialize()
                self._cluster_nodes_data = cluster_nodes_data

            clients = []
            nodes = redisclient.get_nodes()
            failed_nodes = []
            #create the redis connection if not created before
            redisclient.nodes_manager.create_redis_connections(nodes)

            for group in redisclient._groups:
                for groupnode in group:
                    node = redisclient.nodes_manager.get_node(node_name=groupnode)
                    if node:
                        clients.append([groupnode,node.redis_connection])
                    else:
                        clients.append([groupnode,None])
                        failed_nodes.append(groupnode)

            clients.sort(key=lambda c:c[0])
            self._server_clients = clients
            self._failed_cluster_nodes = failed_nodes

        return self._server_clients

