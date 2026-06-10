from datetime import timedelta
from itertools import chain
import redis
import logging

from django.core.cache.backends import redis as django_redis
from django.utils import timezone
from django.utils.functional import cached_property

from .. import utils
from ..serializers import Processtime
from .base import CacheMixin

logger = logging.getLogger(__name__)

class BaseRedisCacheClient(django_redis.RedisCacheClient):
    """
    A base django redis cache client which holds a redis client to access a redis server or a list of redis server

    """
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
    """
    A django redis cache client for a single redis server 
    it holds a redis client to access a single redis server
    """
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
    """
    A django redis cache client for a list of redis server
    it holds a redis client to access a list of redis server
    The redis client
    """
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
        client = self._redisclients.get(index)
        if not client:
            pool = self._pool_class.from_url(self._servers[index],**self._pool_options)
            self._pools[index] = pool
            client = self._client(connection_pool=pool)
            self._redisclients[index] = client

        return client

class RedisCache(CacheMixin,django_redis.RedisCache):
    """
    A django cache which hold a django redis cache client to access redis service
    """
    _redis_client = None
    def __init__(self, server, params):
        if self.cacheid:
            #already initialized, 
            return
        self.cacheid = params.pop("CACHEID")
        super().__init__(server,params)
        if len(self._servers) == 1:
            self._class = RedisCacheClient
        else:
            self._class = MultiRedisCacheClient

        
    @cached_property
    def redis_client(self):
        """
        A cached redis client to access a redis server
        If the redis cache backed by a list of redis server, the redis client is the redis client of the first redis server

        """
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
        """
        Return (True if all redis servers are available, otherwise False,dict of each redis server's ping status)
        """
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
        """
        Return 
           A single redis server: a tuple(server url, redis client) 
           A list of redis server: a list of tuple(server url, redis client)

        """
        if len(self._servers) == 1:
            return (self._servers[0],self._cache.get_client_by_index(0))
        else:
            return [(self._servers[i],self._cache.get_client_by_index(i)) for i in range(len(self._servers))]

