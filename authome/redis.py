import re
from datetime import timedelta
import time
from itertools import chain
import redis
from redis.cluster import PRIMARY,REPLICA
from redis.exceptions import ConnectionError,TimeoutError,ClusterError,RedisClusterException
from collections import OrderedDict
import logging

from django.core.cache.backends import redis as django_redis
from django.utils import timezone
from django.utils.functional import cached_property
from django.conf import settings

from . import utils
from .serializers import Processtime

logger = logging.getLogger(__name__)

def is_cluster(url):
    ex = None
    for redisurl in url.split(";"):
        redisurl = redisurl.strip()
        if not redisurl:
            continue
        client = None
        try:
            client = redis.Redis.from_url(redisurl)
            data = client.info("cluster")
            logger.debug("Redis server({}) is cluster {}".format(redisurl,"enabled" if data["cluster_enabled"] else "disabled"))
            return True if data["cluster_enabled"] else False
        except Exception as e:
            if client:
                client.close()
            ex = e
    if ex:
        raise Exception("No available redis server.{}".format(str(ex)))
    else: 
        raise Exception("No available redis server.")

redis_re = re.compile("^\\s*((?P<protocol>[a-zA-Z]+)://((?P<user>[^:@]+)?(:(?P<password>[^@]+)?)?@)?)?(?P<host>[^:/]+)(:(?P<port>[0-9]+))?(/(?P<db>[0-9]+))?\\s*$")
class CacheMixin(object):
    _parsed_servers = {}
    _instances = {}
    cacheid = None

    def __new__(cls,server,params):
        cacheid = params["CACHEID"]
        try:
            return cls._instances[cacheid]
        except KeyError as ex:
            o = super().__new__(cls)
            cls._instances[cacheid] = o
            return o

    @cached_property
    def _cache(self):
        if len(self._servers) == 1:
            return self._class(self._servers[0], **self._options)
        else:
            return self._class(self._servers, **self._options)

    def ttl(self, key):
        return self._cache.ttl(self.make_and_validate_key(key))
        
    def expire(self, key,timeout):
        return self._cache.expire(self.make_and_validate_key(key), timeout)
        
    def _parse_server(self,server=None):
        """
        Parse server url to protocol, server and db
        """
        if not server:
            server = self._servers[0]
        if server not in self._parsed_servers:
            server_data = {}
            self._parsed_servers[server] = server_data
            m = redis_re.search(server)
            if m:
                server_data["protocol"] = m.group("protocol") or "redis"
                server_data["server"] = "{}:{}".format(m.group("host"),m.group("port") or 6379)
                server_data["db"] = int(m.group("db") or 0)
                server_data["server4print"] = "{0}://***:***@{1}:{2}/{3}".format(server_data["protocol"],m.group("host"),m.group("port") or 6379,server_data["db"])
            else:
                server_data["server4print"] = "******"
                server_data["server"] = "N/A"
                server_data["db"] = -1
                server_data["protocol"] = "N/A"


    @property
    def server4print(self):
        """
        Return a printable redis server url
        only support single redis server per cache
        """
        return self.get_server4print()

    def get_server4print(self,server=None):
        if not server:
            server = self._servers[0]

        self._parse_server(server)
        return self._parsed_servers[server]["server4print"]

    @property
    def db(self):
        server = self._servers[0]
        self._parse_server(server)
        return self._parsed_servers[server]["db"]


    def _get_server_status(self,redisclient):
        if not redisclient[1]:
            return (False,"{} : status = Offline".format(self.get_server4print(redisclient[0])))
        serverinfo = ""
        try:
            data = redisclient[1].info()
            serverinfo = self.get_serverinfo(data)

            healthy = True
            msg = "OK"
        except Exception as ex:
            healthy = False
            msg = str(ex)
        try:
            connections = redisclient[1].connection_pool._created_connections
            max_connections = redisclient[1].connection_pool.max_connections
            max_connections = max_connections if max_connections and max_connections > 0 else "Not configured"
            
            if healthy:
                return (healthy,"{} : connections = {} , max connections = {} , {} , status = OK".format(
                            self.get_server4print(redisclient[0]),
                            connections,
                            max_connections,
                            serverinfo
                        ))
            else:
                return (healthy,"{} : connections = {} , max connections = {} , {} , error = {}".format(
                            self.get_server4print(redisclient[0]),
                            connections,
                            max_connections,
                            serverinfo,
                            msg
                        ))
        except:
            return (healthy,"{} : {} , error = {}".format(
                        self.get_server4print(redisclient[0]),
                        serverinfo,
                        msg
                    ))


    @property
    def server_status(self):
        clients = self._redis_server_clients
        if isinstance(clients,list):
            if len(clients) == 0:
                return (False,"No redis server found")
            else:
                healthy = True
                msgs = []
                for client in clients:
                    client_status = self._get_server_status(client)
                    if client_status is None:
                        continue
                    if not client_status[0]:
                        healthy = False
                    msgs.append(client_status[1])
    
                return (healthy,msgs)

        else:
            return self._get_server_status(clients)

    def ping_redis(self,redisclient):
        try:
            if not redisclient[1]:
                return (False,"{} is offline".format(self.get_server4print(redisclient[0])))
            elif redisclient[1].ping():
                return (True,None)
            else:
                return (False,"{} is offline".format(self.get_server4print(redisclient[0])))
        except Exception as ex:
            return (False,"{} is offline.{}".format(self.get_server4print(redisclient[0]),str(ex)))
    
class BaseRedisCacheClient(django_redis.RedisCacheClient):
    def __init__(self, servers, **options ):
        #config the retry attempts
        retry_attempts = options.pop('retry_attempts',0)
        if retry_attempts >= 1:
            options["retry"] = redis.retry.Retry(redis.backoff.NoBackoff(),retry_attempts)
        super().__init__(servers,**options)
           
    def ttl(self, key):
        client = self.get_client(key)
        return client.ttl(key)

    def expire(self, key,timeout):
        client = self.get_client(key, write=True)
        return client.expire(key,timeout)

class RedisCacheClient(BaseRedisCacheClient):
    _redisclient = None
    def get_client(self, key=None, *, write=False):
        # key is used so that the method signature remains the same and custom
        # cache client can be implemented which might require the key to select
        # the server, e.g. sharding.
        if not self._redisclient:
            pool = self._pool_class.from_url(
                self._servers,
                **self._pool_options,
            )
            self._redisclient = self._client(connection_pool=pool)
        return self._redisclient

    def get_client_by_index(self,index=0):
        # key is used so that the method signature remains the same and custom
        # cache client can be implemented which might require the key to select
        # the server, e.g. sharding.
        return self.get_client()

class MultiRedisCacheClient(BaseRedisCacheClient):
    _redisclients = {}
    def get_client(self, key=None, *, write=False):
        # key is used so that the method signature remains the same and custom
        # cache client can be implemented which might require the key to select
        # the server, e.g. sharding.
        index = self._get_connection_pool_index(write)
        if index not in self._redisclients:
            pool = self._pool_class.from_url(self._servers[index],**self._pool_options)
            self._pools[index] = pool
            self._redisclients[index] = self._client(connection_pool=pool)

        return self._redisclients[index]

    def get_client_by_index(self,index):
        # key is used so that the method signature remains the same and custom
        # cache client can be implemented which might require the key to select
        # the server, e.g. sharding.
        if index not in self._redisclients:
            pool = self._pool_class.from_url(self._servers[index],**self._pool_options)
            self._pools[index] = pool
            self._redisclients[index] = self._client(connection_pool=pool)

        return self._redisclients[index]

class RedisCache(CacheMixin,django_redis.RedisCache):
    _redis_client = None
    def __init__(self, server, params):
        if self.cacheid:
            return
        self.cacheid = params.pop("CACHEID")
        super().__init__(server,params)
        if len(self._servers) == 1:
            self._class = RedisCacheClient
        else:
            self._class = MultiRedisCacheClient

        
    @cached_property
    def redis_client(self):
            return self._cache.get_client_by_index(0)

    def get_serverinfo(self,data):
        return "system_memory = {} , used_memory = {} , keys = {} , starttime = {} , redis_version = {}".format(
            data.get("total_system_memory_human","N/A"),
            data.get("used_memory_human","N/A"),
            data.get("db{}".format(self.db),{}).get("keys","0") if self.db >= 0 else "N/A",
            utils.format_datetime(timezone.localtime() - timedelta(seconds=data.get("uptime_in_seconds"))) if "uptime_in_seconds" in data else "N/A",
            data.get("redis_version","N/A"),
        )


    def ping(self):
        redisclients = self._redis_server_clients
        pingstatus = {}
        starttime = None
        working = True
        if isinstance(redisclients,list):
            for redisclient in redisclients:
                starttime = timezone.localtime()
                status = self.ping_redis(redisclient)
                pingstatus[redisclient[0]] = {"ping":status[0],"pingtime":Processtime((timezone.localtime() - starttime).total_seconds())}
                if not status[0]:
                    working = False
                    if status[1]:
                        pingstatus[redisclient[0]]["error"] = status[1]
        else:
            starttime = timezone.localtime()
            status = self.ping_redis(redisclients)
            pingstatus[redisclients[0]] = {"ping":status[0],"pingtime":Processtime((timezone.localtime() - starttime).total_seconds())}
            if not status[0]:
                working = False
                if status[1]:
                    pingstatus[redisclients[0]]["error"] = status[1]
        return (working,pingstatus)
        
    @cached_property
    def _redis_server_clients(self):
        if len(self._servers) == 1:
            return (self._servers[0],self._cache.get_client_by_index(0))
        else:
            return [(self._servers[i],self._cache.get_client_by_index(i)) for i in range(len(self._servers))]

class RedisClusterMixin(object):
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

class RedisCluster(RedisClusterMixin,redis.RedisCluster):
    pass
            
class AutoFailoverRedisCluster(RedisClusterMixin,redis.RedisCluster):

    def find_another_default_node(self):
        curr_node = self.get_default_node()
        tried_nodes = set()
        tried_nodes.add(curr_node.name)
        #try to find a default node from primary nodes and then replica nodes
        for node in chain(self.get_primaries(),self.get_replicas()):
            if node.name in tried_nodes:
                continue
            tried_nodes.add(node.name)
            try:
                if self._execute_command(node,"PING"):
                    return node
            except:
                continue

        #can't find a node from nodes_manager, try to find a accessible node from all nodes of the redis cluster.
        for group in self._groups:
            for groupnode in group:
                if groupnode in tried_nodes:
                    continue
                if ":" in groupnode:
                    host,port = groupnode.split(":")
                    port = int(port)
                else:
                    host = groupnode
                    port = 6379
                    
                node = self.nodes_manager._get_or_create_cluster_node(host, port,REPLICA,self.nodes_manager.nodes_cache)
                self.nodes_manager.create_redis_connections([node])
                try:
                    if self._execute_command(node,"PING"):
                        #the node is accessible
                        #send a failover command to switch the node to master
                        resp = super()._execute_command(node,"CLUSTER FAILOVER","TAKEOVER")
                        new_master = None
                        attempts = 0
                        while attempts < 10:
                            nodes2 = self._execute_command(node,"CLUSTER NODES")
                            if "master" in nodes2[groupnode]["flags"] and "fail" not in nodes2[groupnode]["flags"]:
                                #switched successfully
                                new_master = groupnode
                                logger.debug("Succeed to switch the node({}) to master node.".format(groupnode))
                                break
                            else:
                                for groupnode2 in group:
                                    if groupnode2 == failed_node:
                                        continue
                                    if "master" in nodes2[groupnode2]["flags"] and "fail" not in nodes2[groupnode2]["flags"]:
                                        #another node was chosen by redis cluster as master node
                                        new_master = groupnode2
                                        logger.debug("Try to switch the node({}) to master node, but the node({}) was chosen by redis as master node".format(groupnode,groupnode2))
                                        break
                                attempts += 1
                                if attempts < 10:
                                    time.sleep(0.2)
                                else:
                                    new_master = None
                        if new_master:
                            #find a new master, initialize the nodes manager
                            #reinitialize nodes manager
                            self.init_nodesmanager_with_new_master(new_master)
        
                            return self.nodes_manager.get_node(node_name=new_master)
                        else:
                            continue
                except:
                    continue
        return None

    def get_cluster_nodes(self,failed_node):
        ex =  None
        tried_nodes = set()
        if failed_node:
            tried_nodes.add(failed_node)
        for attempt in range(2):
            #first round , try primary nodes
            #second round, try replica nodes
            for group in self._groups:
                for groupnode in group:
                    if  groupnode in tried_nodes:
                        continue
                    node = self.nodes_manager.get_node(node_name=groupnode)
                    if not node:
                        continue
                    if node.server_type == (PRIMARY if attempt == 1 else REPLICA): 
                        tried_nodes.add(groupnode)
                        if not node.redis_connection:
                            continue
                    else:
                        continue

                    try:
                        return self._execute_command(node,"CLUSTER NODES")
                    except Exception as e:
                        continue
                        
        chosed_node = None
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
                    seconds = self._execute_command(node,"info","server").get("uptime_in_seconds",0)
                    if uptime < seconds:
                        uptime = seconds
                        chosed_node = node
                except Exception as e:
                    ex = e

        if chosed_node:
            try:
                return self._execute_command(chosed_node,"CLUSTER NODES")
            except Exception as e:
                ex = e

        raise ex

    def init_nodesmanager_with_new_master(self,new_master):
        #the new master is one of the startup nodes, move the new master to the first node of the startup nodes
        if isinstance(new_master,str):
            master_node = self.nodes_manager.get_node(node_name=new_master)
        else:
            master_node = new_master
            new_master = master_node.name
 
        added = False
        if not isinstance(self.nodes_manager.startup_nodes,OrderedDict):
            startup_nodes = OrderedDict(self.nodes_manager.startup_nodes)
            self.nodes_manager.startup_nodes = startup_nodes

        if new_master not in self.nodes_manager.startup_nodes:
            if not master_node:
                if ":" in new_master:
                    host,port = new_master.split(":")
                    port = int(port)
                else:
                    host = new_master
                    port = 6379
                
                master_node = self.nodes_manager._get_or_create_cluster_node(host, port,PRIMARY,self.nodes_manager.nodes_cache)
            self.nodes_manager.create_redis_connections([master_node])
            self.nodes_manager.startup_nodes[new_master] = master_node
            added = True

        self.nodes_manager.startup_nodes.move_to_end(new_master,last=False)

        self.nodes_manager.initialize()
        logger.debug("{}: redis cluster nodes:{}".format(utils.get_processid(),self.nodes_manager.nodes_cache))
        if added and not self.dynamic_startup_nodes:
            #the new_master node was newly added to startup_nodes and dynamic_startup_nodes is False, remove the new_master from startup_nodes
            self.nodes_manager.startup_nodes.pop(new_master,None)
        
    def master_failover(self,failed_node=None,host=None,port=None,prefered_master=None,node=None):
        """
        Return True if switch succeed; otherwise return False
        """
        checked_servers = None
        failed_slot = None
        new_master = None
        
        #locate the failed node via host and port
        if  failed_node:
            failed_node = failed_node.name
        elif host:
            failed_node = "{}:{}".format(host,port or 6379)

        if prefered_master and not isinstance(prefered_master,str):
            prefered_master = prefered_master.name
            
        if node and not isinstance(node,str):
            node = node.name
            
        if failed_node and failed_node not in self._groupmap:
            logger.debug("Can't find the redis group for the node({})".format(failed_node))
            return None

        if not failed_node and not prefered_master and not node:
            return None

        group = self._groupmap[failed_node or prefered_master or node]
        nodes = self.get_cluster_nodes(failed_node)

        tried_nodes = set()
        if failed_node:
            tried_nodes.add(failed_node)

        for attempt in range(5):
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
                    if not prefered_master:
                        #no prefered master
                        break
                    elif groupnode != prefered_master:
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
                    master_node = self.nodes_manager.get_node(node_name = groupnode)
                    if not master_node:
                        #can't find the node from node_manager, maybe majority of redis master are down, try to create a node manually
                        if ":" in groupnode:
                            host,port = groupnode.split(":")
                            port = int(port)
                        else:
                            host = groupnode
                            port = 6379
                            
                        master_node = self.nodes_manager._get_or_create_cluster_node(host, port,PRIMARY,self.nodes_manager.nodes_cache)
                        self.nodes_manager.create_redis_connections([master_node])

                    resp = super()._execute_command(master_node,"CLUSTER FAILOVER","TAKEOVER")
                    new_master = None
                    try_time = 0
                    while try_time < 10:
                        nodes2 = self._execute_command(master_node,"CLUSTER NODES")
                        if "master" in nodes2[groupnode]["flags"] and "fail" not in nodes2[groupnode]["flags"]:
                            #switched successfully
                            new_master = groupnode
                            logger.debug("{}: Succeed to switch the node({}) to master node.".format(utils.get_processid(),groupnode))
                        else:
                            for groupnode2 in group:
                                if failed_node and groupnode2 == failed_node:
                                    continue
                                if "master" in nodes2[groupnode2]["flags"] and "fail" not in nodes2[groupnode2]["flags"]:
                                    #another node was chosen by redis cluster as master node
                                    new_master = groupnode2
                                    logger.debug("{}: Try to switch the node({}) to master node, but the node({}) was chosen by redis as master node".format(utils.get_processid(), groupnode,groupnode2))
                                    break
                        if new_master:
                            break
                        else:
                            try_time += 1
                            if try_time < 10:
                                time.sleep(0.2)
                            else:
                                new_master = None
                    if new_master:
                        #reinitialize nodes manager
                        self.init_nodesmanager_with_new_master(new_master)
                        return new_master
                    else:
                        logger.warning("{}: Failed to switch the node({}) to master node without exception, try another node".format(utils.get_processid(),groupnode))
                except redis.ResponseError as ex:
                    if "You should send CLUSTER FAILOVER to a replica" in str(ex):
                        #already switched
                        logger.debug("{}: The new master({}) was already chosen by redis cluster".format(utils.get_processid(), groupnode))
                        new_master = groupnode
                        self.init_nodesmanager_with_new_master(master_node)
                        return new_master
                    else:
                        logger.warning("{}: Failed to switch the node({}) to master node, try another one.{}".format(utils.get_processid(),groupnode,ex))
                        continue
                except Exception as ex:
                    logger.warning("{}: Failed to switch the node({}) to master node, try another one.{}".format(utils.get_processid(),groupnode,ex))
                    continue
        if failed_node:
            logger.warning("{}: Failed to find an accessible slave to replace the current master({})".format(utils.get_processid(),failed_node))
        else:
            logger.warning("{}: Failed to find an accessible slave to act as the new master, prefered master is {}".format(utils.get_processid(),prefered_master))
        return None

    def execute_command(self, *args, **kwargs):
        """
        Wrapper for ERRORS_ALLOW_RETRY error handling.

        It will try the number of times specified by the config option
        "self.cluster_error_retry_attempts" which defaults to 3 unless manually
        configured.

        If it reaches the number of times, the command will raise the exception

        Key argument :target_nodes: can be passed with the following types:
            nodes_flag: PRIMARIES, REPLICAS, ALL_NODES, RANDOM
            ClusterNode
            list<ClusterNode>
            dict<Any, ClusterNode>
        """
        target_nodes_specified = False
        is_default_node = False
        target_nodes = None
        passed_targets = kwargs.pop("target_nodes", None)
        if passed_targets is not None and not self._is_nodes_flag(passed_targets):
            target_nodes = self._parse_target_nodes(passed_targets)
            target_nodes_specified = True
        # If an error that allows retrying was thrown, the nodes and slots
        # cache were reinitialized. We will retry executing the command with
        # the updated cluster setup only when the target nodes can be
        # determined again with the new cache tables. Therefore, when target
        # nodes were passed to this function, we cannot retry the command
        # execution since the nodes may not be valid anymore after the tables
        # were reinitialized. So in case of passed target nodes,
        # retry_attempts will be set to 0.
        retry_attempts = (
            0 if target_nodes_specified else self.cluster_error_retry_attempts
        )
        # Add one for the first execution
        execute_attempts = 1 + retry_attempts
        current_node = None
        for failover_times in range(2):
            retry_attempts = execute_attempts - 1
            for _ in range(execute_attempts):
                try:
                    res = {}
                    if not target_nodes_specified:
                        # Determine the nodes to execute the command on
                        target_nodes = self._determine_nodes(
                            *args, **kwargs, nodes_flag=passed_targets
                        )
                        if not target_nodes:
                            raise RedisClusterException(
                                f"No targets were found to execute {args} command on"
                            )
                        if (
                            len(target_nodes) == 1
                            and target_nodes[0] == self.get_default_node()
                        ):
                            is_default_node = True
                    for node in target_nodes:
                        current_node = node
                        res[node.name] = self._execute_command(node, *args, **kwargs)
                    # Return the processed result
                    return self._process_result(args[0], res, **kwargs)
                except Exception as e:
                    if retry_attempts > 0 and (is_default_node or  type(e) in self.__class__.ERRORS_ALLOW_RETRY):
                        if is_default_node:
                            # Replace the default cluster node
                            default_node = self.find_another_default_node()
                            if default_node:
                                self.replace_default_node(default_node)
                            else:
                                raise e
                        # The nodes and slots cache were reinitialized.
                        # Try again with the new cluster setup.
                        retry_attempts -= 1
                        continue
                    elif failover_times:
                        #already try
                        logger.debug("{}: Failed to execute command({}) on node({}),{}".format(utils.get_processid(),args,target_nodes,e))
                        raise e
                    else:
                        # raise the exception
                        if not current_node :
                            raise e
                        elif current_node.server_type != PRIMARY:
                            #current node is not master, no need to switch
                            raise e
                        elif type(e) in (ConnectionError,TimeoutError):
                            logger.info("{}: Master failover action was triggered by command({}) on node({}) with exception({}:{})".format(utils.get_processid(),args,current_node,e.__class__.__name__,str(e)))
                            new_master = self.master_failover(failed_node=current_node)
                            if new_master:
                                #specify the target node to execute the command
                                logger.debug("{}: try to execute command({}) on nodes({}={})".format(utils.get_processid(), args,new_master, self.nodes_manager.get_node(node_name=new_master)))
                                target_nodes_specified = True
                                if target_nodes:
                                    target_nodes.clear()
                                    target_nodes.append(self.nodes_manager.get_node(node_name=new_master))
                                else:
                                    target_nodes = [self.nodes_manager.get_node(node_name=new_master)]
                            else:
                                #failed to switch the replica to primary
                                raise e
                        elif isinstance(e, RedisClusterException):
                            logger.info("{}: Master failover action was triggered by command({}) on node({}) with exception({}:{})".format(utils.get_processid(),args,current_node,e.__class__.__name__,str(e)))
                            new_master = self.master_failover(node=current_node)
                            if new_master:
                                #specify the target node to execute the command
                                logger.debug("{}: try to execute command({}) on nodes({}={})".format(utils.get_processid(), args,new_master, self.nodes_manager.get_node(node_name=new_master)))
                                target_nodes_specified = True
                                if target_nodes:
                                    target_nodes.clear()
                                    target_nodes.append(self.nodes_manager.get_node(node_name=new_master))
                                else:
                                    target_nodes = [self.nodes_manager.get_node(node_name=new_master)]
                            else:
                                #failed to switch the replica to primary
                                raise e
                        elif isinstance(e , ClusterError):
                            logger.info("{}: Master failover action was triggered by command({}) on node({}) with exception({}:{})".format(utils.get_processid(),args,current_node,e.__class__.__name__,str(e)))
                            new_master = self.master_failover(prefered_master=current_node)
                            if new_master:
                                logger.debug("{}: try to execute command({}) on nodes({}={})".format(utils.get_processid(), args,new_master, self.nodes_manager.get_node(node_name=new_master)))
                                #specify the target node to execute the command
                                target_nodes_specified = True
                                if target_nodes:
                                    target_nodes.clear()
                                    target_nodes.append(self.nodes_manager.get_node(node_name=new_master))
                                else:
                                    target_nodes = [self.nodes_manager.get_node(node_name=new_master)]
                                break
                            else:
                                #failed to switch the replica to primary
                                raise e
                        else:
                            raise e
                        
class RedisClusterCacheClient(django_redis.RedisCacheClient):
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
        # key is used so that the method signature remains the same and custom
        # cache client can be implemented which might require the key to select
        # the server, e.g. sharding.
        if not self._redisclient:
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
    _server_clients = []
    _failed_cluster_nodes = []

    def __init__(self, server, params):
        if self.cacheid:
            return
        self.cacheid = params.pop("CACHEID")
        server = server.strip(" ;")
        super().__init__(server,params)
        self._class = RedisClusterCacheClient

    @cached_property
    def redis_client(self):
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
        from .cache import cache

        redisclients = self._redis_server_clients
        starttime = None
        pingstatus = {}
        for redisclient in redisclients:
            starttime = timezone.localtime()
            status = self.ping_redis(redisclient)
            pingstatus[redisclient[0]] = {"ping":status[0],"pingtime":Processtime((timezone.localtime() - starttime).total_seconds())}
            if not status[0]:
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
            pingstatus["error"] = "The whole redis cluster is offline"
            return (False,pingstatus)
        else:
            errors = None
            for group in offline_groups:
                errors = utils.add_to_list(errors,"The whole redis cluster group({}) is offline.".format(group))
            for group,failed_nodes in partially_failed_groups:
                if len(failed_nodes) == 1:
                    errors = utils.add_to_list(errors,"The node({1}) in redis cluster group({0}) is offline.".format(group,failed_nodes[0]))
                else:
                    errors = utils.add_to_list(errors,"The nodes({1}) in redis cluster group({0}) are offline.".format(group,failed_nodes))
            
            pingstatus["errors"] = errors

            return (False if offline_groups else True,pingstatus)

    def _get_server_status(self,redisclient):
        result = super()._get_server_status(redisclient)
        if not result[0]:
            if redisclient[0] not in self._failed_cluster_nodes:
                self._failed_cluster_nodes.append(redisclient[0])
        return result

    @property   
    def _redis_server_clients(self):
        redisclient = self.redis_client
        refreshed = False

        if len(redisclient._groupmap) != len(redisclient.nodes_manager.nodes_cache) or self._failed_cluster_nodes:
            redisclient.nodes_manager.initialize()
            refreshed = True

        if len(self._server_clients) != len(redisclient._groupmap) or refreshed:
            #cached server_clients doesn't match with the nodes_cache
            clients = []
            nodes = redisclient.get_nodes()
            failed_nodes = []
            #create the redis connection if not created before
            redisclient.nodes_manager.create_redis_connections(nodes)

            for group in redisclient._groups:
                for groupnode in group:
                    node = redisclient.nodes_manager.get_node(node_name=groupnode)
                    if node:
                        clients.append((groupnode,node.redis_connection))
                    else:
                        clients.append((groupnode,None))
                        failed_nodes.append(groupnode)

            clients.sort(key=lambda c:c[0])
            self._server_clients = clients
            self._failed_cluster_nodes = failed_nodes

        return self._server_clients

