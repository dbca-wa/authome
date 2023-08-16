import re
from datetime import timedelta

from django.core.cache.backends import redis as django_redis
from django.utils import timezone

from . import utils


class CacheMixin(object):
    _server4print = None

    _redis_re = re.compile("^\s*(?P<protocol>[a-zA-Z]+)://((?P<user>[^:@]+)?(:(?P<password>[^@]+))?@)?(?P<server>\S+)\s*$")
    @property
    def server4print(self):
        """
        Return a printable redis server url
        only support single redis server per cache
        """
        if not self._server4print:
            try:
                m = self._redis_re.search(self._servers[0])
                self._server4print = "{0}://xxx:xxx@{1}".format(m.group("protocol"),m.group("server"))
            except:
                self._server4print = "xxxxxx"

        return self._server4print

class RedisCache(CacheMixin,django_redis.RedisCache):
    @property
    def redis_client(self):
        return self._cache.get_client()

    def ping(self):
        try:
            if self.redis_client.ping():
                return (True,"OK")
            else:
                return (False,"Failed")
        except Exception as ex:
            return (False,str(ex))
            healthy = False
            msg = str(ex)
    
    @property
    def server_status(self):
        connections = self.redis_client.connection_pool._created_connections
        max_connections = self.redis_client.connection_pool.max_connections
        max_connections = max_connections if max_connections and max_connections > 0 else "Not configured"

        serverinfo = ""
        try:
            data = self.redis_client.info("server")
            if data.get("uptime_in_seconds"):
                serverinfo = "starttime = {}".format( utils.format_datetime(timezone.localtime() - timedelta(seconds=data.get("uptime_in_seconds"))) )
            else:
                serverinfo = "starttime = N/A"

            healthy = True
            msg = "OK"
        except Exception as ex:
            healthy = False
            msg = str(ex)

        return (healthy,"server = {} , connections = {} , max connections = {} , {} , status = {}".format(
                    self.server4print,
                    connections,
                    max_connections,
                    serverinfo,
                    msg
                ))

class RedisClusterCacheClient(django_redis.RedisCacheClient):
    def __init__(self, *args,**kwargs):
        import redis
        super().__init__(*args,**kwargs)
        self._client = redis.RedisCluster
        
    def _get_server(self, write):
        # Write to the first server. Read from other servers if there are more,
        # otherwise read from the first server.
        if write or len(self._servers) == 1:
            return self._servers[0]
        return self._servers[random.randint(1, len(self._servers) - 1)]

    def get_client(self, key=None, *, write=False):
        # key is used so that the method signature remains the same and custom
        # cache client can be implemented which might require the key to select
        # the server, e.g. sharding.
        return self._client.from_url(self._get_server(write),**self._pool_options)


class RedisClusterCache(CacheMixin,django_redis.RedisCache):
    def __init__(self, *args,**kwargs):
        super().__init__(*args,**kwargs)
        self._class = RedisClusterCacheClient

    @property
    def redis_client(self):
        return self._cache.get_client()
