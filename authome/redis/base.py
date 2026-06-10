import re
import traceback
import logging

from django.utils.functional import cached_property

logger = logging.getLogger(__name__)

redis_re = re.compile("^\\s*((?P<protocol>[a-zA-Z]+)://((?P<user>[^:@]+)?(:(?P<password>[^@]+)?)?@)?)?(?P<host>[^:/]+)(:(?P<port>[0-9]+))?(/(?P<db>[0-9]+))?\\s*$")
class CacheMixin(object):
    """
    Provide common features for django redis cache, including redis cache and redis cluster cache
    """
    _servers_metadta = {}
    _instances = {}
    cacheid = None

    def __new__(cls,server:(list[str],str),params:dict) -> object:
        """
        Implement a singleton pattern for each cache
        Everytime creating a redis cache with the same cacheid will return the same django cache instance.
        server: 
            Redis Server:a list of redis server, or a ";" separated string list 
            Redis Cluster: a redis cluster server or a ";" separated string list
        """
        cacheid = params["CACHEID"]
        try:
            return cls._instances[cacheid]
        except KeyError as ex:
            o = super().__new__(cls)
            cls._instances[cacheid] = o
            return o

    @cached_property
    def _cache(self):
        """
        Return a cached django redis/rediscluster cache client 
        Django redis/rediscluster cache client will hold the redis/rediscluster client to access redis/rediscluster
        """
        if len(self._servers) == 1:
            return self._class(self._servers[0], **self._options)
        else:
            return self._class(self._servers, **self._options)

    def ttl(self, key:str):
        return self._cache.ttl(self.make_and_validate_key(key))
        
    def expire(self, key,timeout):
        return self._cache.expire(self.make_and_validate_key(key), timeout)
        
    def get_server_metadata(self,server=None):
        """
        Parse server url to protocol, server and db .
        """
        if not server:
            server = self._servers[0]
        server_data = self._servers_metadta.get(server)
        if not server_data:
            server_data = {}
            self._servers_metadta[server] = server_data
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

        return server_data


    @property
    def server4print(self):
        """
        Return a printable redis server url
        only support single redis server per cache
        """
        return self.get_server_metadata()["server4print"]

    def get_server4print(self,server:str=None):
        return self.get_server_metadata(server)["server4print"]

    @property
    def db(self):
        """
        Return the redis db index 
        """
        return self.get_server_metadata()["db"]

    def get_serverinfo(self,data):
        """
        Return the server status description from server information info data returned from redis command 'info'
        """
        return ""


    def _get_server_status(self,redisclient:list,retry:int=1):
        """
        redisclient: a list with two members [redis server url, redis client]
        Return the redis server status
        """
        if not redisclient[1]:
            return (False,"{} : status = Offline".format(self.get_server4print(redisclient[0])))
        serverinfo = ""
        for i in range(retry):
            try:
                data = redisclient[1].info()
                serverinfo = self.get_serverinfo(data)
                healthy = True
                msg = "OK"
                break
            except Exception as ex:
                healthy = False
                msg = "Error: {}".format(str(ex))
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
        """
        Return the status of all redis server accessed by the redis/rediscluster cache
        Can be a single redis server, a list of redis server or a redis cluster
        """
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

    def ping_redis(self,redisclient:list,retry:int=1):
        """
        redisclient: a list with two members [redis server url, redis client]
        Return (True,None) if ping succeed; otherwise return (False,message)
        """
        try:
            if not redisclient[1]:
                return (False,"{} is offline".format(self.get_server4print(redisclient[0])))
            elif retry == 1:
                if redisclient[1].ping():
                    return (True,None)
                else:
                    return (False,"{} is offline".format(self.get_server4print(redisclient[0])))
            else:
                for i in range(retry):
                    if redisclient[1].ping():
                        return (True,None)

                return (False,"{} is offline".format(self.get_server4print(redisclient[0])))

        except Exception as ex:
            return (False,"{} is offline.{}".format(self.get_server4print(redisclient[0]),str(ex)))
    
