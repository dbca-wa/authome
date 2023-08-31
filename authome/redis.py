import re
from datetime import timedelta
import redis
from collections import OrderedDict
import logging

from django.core.cache.backends import redis as django_redis
from django.utils import timezone
from django.utils.functional import cached_property
from django.conf import settings

from . import utils

logger = logging.getLogger(__name__)

def is_cluster(url):
    ex = None
    for redisurl in url.split(";"):
        redisurl = redisurl.strip()
        if not redisurl:
            continue
        client = None
        try:
            client = redis.Redis.from_url(url)
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

redis_re = re.compile("^\s*((?P<protocol>[a-zA-Z]+)://((?P<user>[^:@]+)?(:(?P<password>[^@]+)?)?@)?)?(?P<host>[^:/]+)(:(?P<port>[0-9]+))?(/(?P<db>[0-9]+))?\s*$")
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
            if redisclient[1].ping():
                return (True,None)
            else:
                return (False,"{} is offline".format(self.get_server4print(redisclient[0])))
        except Exception as ex:
            return (False,"{} is not accessible.{}".format(self.get_server4print(redisclient[0]),str(ex)))
    
class BaseRedisCacheClient(django_redis.RedisCacheClient):
    def __init__(self, servers, **options ):
        #config the retry attempts
        retry_attempts = options.pop('retry_attempts',0)
        if retry_attempts >= 1:
            options["retry"] = redis.retry.Retry(redis.backoff.NoBackoff(),retry_attempts)
        super().__init__(servers,**options)
           
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
        if isinstance(redisclients,list):
            working = True
            errors = []
            for redisclient in redisclients:
                status = self.ping_redis(redisclient)
                if not status[0]:
                    working = False
                    errors.append(status[1])
            return (working,errors)
        else:
            return self.ping_redis(redisclients)
        
    @cached_property
    def _redis_server_clients(self):
        if len(self._servers) == 1:
            return (self._servers[0],self._cache.get_client_by_index(0))
        else:
            return [(self._servers[i],self._cache.get_client_by_index(i)) for i in range(len(self._servers))]

class AutoFailoverRedisCluster(redis.RedisCluster):
    def master_failover(self,*args):
        """
        Return True if switch succeed; otherwise return False
        """
        checked_servers = None
        master = None
        new_master = None
        for i in range(2):
            slot = self.determine_slot(*args)
            nodes = self.nodes_manager.slots_cache.get(slot) or []
            for node in nodes:
                if node.server_type == redis.cluster.PRIMARY:
                    if not master:
                        master = node
                    elif master.name != node.name:
                        #master node has been changed, no need to change again.
                        new_master = node
                        break
                    continue
                logger.debug("switch cluster master from {} to {}".format(master,node))
                if checked_servers and node.name in checked_servers:
                    #already checked
                    continue
                try:
                    if checked_servers:
                        checked_servers.add(node.name)
                    else:
                        checked_servers = set((node.name,))
                    resp = super()._execute_command(node,"CLUSTER FAILOVER","TAKEOVER")
                except (redis.ConnectionError, redis.TimeoutError) as ex:
                    #node is not available, try another one
                    logger.debug("The node '{}' is not accessable, try another one")
                    continue
                except redis.ResponseError as ex:
                    if "You should send CLUSTER FAILOVER to a replica" in str(ex):
                        #already switched
                        logger.debug("The node '{}' has already been switched to master".format(node))
                        pass
                    else:
                        #failed to failover, try other node
                        continue

                new_master = node
                break

            if new_master:
                #reinitialize nodes manager
                if isinstance(self.nodes_manager.startup_nodes,OrderedDict):
                    logger.debug("Move the node '{}' to the head to fetch the cluster slots".format(new_master))
                    self.nodes_manager.startup_nodes.move_to_end(new_master.name,last=False)
                else:
                    logger.debug("Change the start_nodes to OrderedMap to fetch the cluster slots from the current node '{}'".format(new_master))
                    nodes = OrderedDict(self.nodes_manager.startup_nodes)
                    nodes.move_to_end(new_master.name,last=False)
                    self.nodes_manager.startup_nodes = nodes

                self.nodes_manager.initialize()
                new_nodes  = self.nodes_manager.slots_cache.get(slot)
                if not new_nodes:
                    break
                if new_nodes[0].name == new_master.name and new_nodes[0].server_type == redis.cluster.PRIMARY:
                    logger.debug("Succeed to switch the master server for slot '{}' from '{}' to '{}',current master is '{}'".format(slot,master,new_master,new_nodes[0]))
                    return True
                else:
                    logger.warning("Failed to switch the master server for slot '{}' from '{}' to '{}',current master is '{}'".format(slot,master,new_master,new_nodes[0]))
                    return False
            else:
                logger.debug("Replica server not found, initialize nodes manager and try again.")
                self.nodes_manager.initialize()

        logger.debug("No replica server are available for slot '{}'".format(slot))
        return False

    def execute_command(self, *args, **kwargs):
        try:
            return super().execute_command(*args,**kwargs)
        except Exception as ex:
            if type(ex) in self.__class__.ERRORS_ALLOW_RETRY:
                self.master_failover(*args)
                return super().execute_command(*args,**kwargs)
            else:
                raise
            
class RedisClusterCacheClient(django_redis.RedisCacheClient):
    _redisclient = None
    def __init__(self, *args,auto_failover=False,**kwargs):
        super().__init__(*args,**kwargs)
        if auto_failover:
            logger.debug("Redis cluster master auto failover feature is enabled. ")
            self._client = AutoFailoverRedisCluster
        else:
            self._client = redis.RedisCluster
        
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
    _cluster_nodes = {}
    _failed_cluster_nodes = []

    def __init__(self, server, params):
        if self.cacheid:
            return
        self.cacheid = params.pop("CACHEID")
        server = server.strip(" ;")
        super().__init__(server,params)
        self._class = RedisClusterCacheClient
        self.refresh_cluster_nodes()

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
        errors = []

        for node in self._failed_cluster_nodes:
            errors.append("{} is offline".format(node["name"]))

        pos = 0
        for redisclient in redisclients:
            status = self.ping_redis(redisclient)
            if not status[0]:
                node = self._cluster_nodes.get(redisclient[0])
                if node:
                    #add the failed nodes to failed nodes
                    if node not in self._failed_cluster_nodes:
                        self._failed_cluster_nodes.append(node)
                        #not in the failed nodes,insert the message to the right position
                        errors.insert(pos,status[1])
                        pos += 1
                else:
                    #not in the failed nodes,insert the message to the right position
                    errors.insert(pos,status[1])
                    pos += 1
                    
        if not self._failed_cluster_nodes:
            working = True
        elif len(self._failed_cluster_nodes) >= len(self._cluster_nodes):
            #all redis are offline
            working = False
        elif all(n["server_type"] == redis.cluster.REPLICA for n in self._failed_cluster_nodes):
            #all failed redis server are replica server
            working = True
        elif all(n["server_type"] == redis.cluster.PRIMARY  for n in self._failed_cluster_nodes):
            #all failed redis server are master server
            working = True
        else:
            #check whether at least one master and its slaves are all failed.
            working = True
            for n in self._cluster_nodes.values():
                if n["server_type"] != redis.cluster.PRIMARY:
                    continue

                if n not in self._failed_cluster_nodes:
                    #is working.
                    continue

                working_slave = None
                for s in n.get("slaves",[]):
                    if s not in self._failed_cluster_nodes:
                        working_slave = s
                        break

                if not working_slave:
                    #all slave server are down
                    working = False
                    break

        return (working,errors)

    def refresh_cluster_nodes(self):
        cluster_nodes = {}
        nodes = self.redis_client.cluster_nodes()
        masters = {}
        failed_cluster_nodes = []
        for key,node in nodes.items():
            if "master" in node["flags"]:
                cluster_nodes[key] = {"name":key,"server_type": redis.cluster.PRIMARY,"available":node["connected"]}
                masters[node["node_id"]] = cluster_nodes[key]
                if not node["connected"]:
                    failed_cluster_nodes.append(cluster_nodes[key])

        for key,node in nodes.items():
            if "master" not in  node["flags"]:
                master = masters.get(node.get("master_id",""),None)
                cluster_nodes[key] = {"name":key,"server_type": redis.cluster.REPLICA,"available":node["connected"],"master":master["name"] if master else "Unknown"}
                if not node["connected"]:
                    failed_cluster_nodes.append(cluster_nodes[key])
                if master:
                    if "slaves" in master:
                        master["slaves"].append(cluster_nodes[key])
                    else:
                        master["slaves"] = [cluster_nodes[key]]

        self._cluster_nodes = cluster_nodes

        failed_cluster_nodes.sort(key=lambda n:n["name"])
        self._failed_cluster_nodes = failed_cluster_nodes

    def _get_server_status(self,redisclient):
        result = super()._get_server_status(redisclient)
        if not result[0]:
            node = self._cluster_nodes.get(redisclient[0])
            if node:
                if node not in self._failed_cluster_nodes:
                    logger.debug("{} is not accessible, add it to failed cluster nodes".format(redisclient[0]))
                    self._failed_cluster_nodes.append(node)
                else:
                    logger.debug("{} is not accessible, but it was already in faiiled cluster nodes".format(redisclient[0]))
                    pass
                #already in failed cluster nodes, server status will be added later.
                return None
        return result

    @property
    def server_status(self):
        result = super().server_status
        if self._failed_cluster_nodes:
            for node in self._failed_cluster_nodes:
                result[1].append("{} : status = offline".format(self.get_server4print(node["name"])))
            return (False,result[1])
        else:
            return result

    @property   
    def _redis_server_clients(self):
        redisclient = self.redis_client
        refreshed = False
        if self._failed_cluster_nodes :
            #_server clients doesn't match with cluster nodes, refresh cluster node first.
            self.refresh_cluster_nodes()
            refreshed = True

        if len(self._cluster_nodes) - len(self._failed_cluster_nodes) != len(redisclient.nodes_manager.nodes_cache) :
            #_server clients doesn't match with cluster nodes, refresh server clients first
            redisclient.nodes_manager.initialize()
            refreshed = True

        if refreshed or not self._server_clients:
            #cached server_clients doesn't match with the nodes_cache
            clients = []
            nodes = redisclient.get_nodes()
            #create the redis connection if not created before
            redisclient.nodes_manager.create_redis_connections(nodes)
            for node in nodes:
                clients.append(("{}:{}".format(node.host,node.port),node.redis_connection))
            clients.sort(key=lambda c:c[0])
            self._server_clients = clients

        return self._server_clients

