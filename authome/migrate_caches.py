import telnetlib
import re
import json
import os
import base64
from datetime import datetime,timedelta


from django.conf import settings
from django.utils import timezone
from django.core.cache.backends.memcached import MemcachedCache
from django.core.cache import _create_cache

from django_redis import get_redis_connection

from authome.cache import get_defaultcache,get_usercache
from authome.cachesessionstore import get_firstsessioncache,SessionStore,process_seq_key

sessionstore = SessionStore('testkey')
firstsessioncache = get_firstsessioncache()
defaultcache = get_defaultcache()

#key used in cache server, including two parts: verion and cache key
cache_key_re = re.compile("^:(?P<version>[^:]+):(?P<cachekey>.+)$".format(settings.SESSION_COOKIE_NAME))

#process_seq key used in django cache
process_seq_key_v1_re = re.compile("^((?P<auth2_prefix>[a-zA-Z0-9_\-]+):)?(?P<key>{})$".format(settings.SESSION_COOKIE_NAME))

#session cache key used by django session store implementation
session_key_v1_re = re.compile("^(?P<session_prefix>django.contrib.sessions.cache)(?P<key>[a-z0-9]{32})$")
#auth2 session cache key , include three parts separated by '-': auth2_prefix(Optional), 'session', session key(process_prefix plus random generated key)
session_key_v2_re = re.compile("^((?P<auth2_prefix>[a-zA-Z0-9_\-]+)\-)?(?P<session_prefix>session)\-(?P<key>([A-Z0-9]+\-)?[a-z0-9]{32})$")
#auth2 session cache key , include three parts separated by ':': auth2_prefix(Optional), 'session', session key(process_prefix plus random generated key)
session_key_v3_re = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<session_prefix>session):(?P<key>([A-Z0-9]+\-)?[a-z0-9]{32})$")

#User key used by dedicated user cache, include two parts separated by '-': auth2_prefix(optional), user id
user_key_v1_re1 = re.compile("^((?P<auth2_prefix>.+)\_)?(?P<key>\-?[0-9]+)$")
#User key used by dedicated user cache, include three parts separated by '-': auth2_prefix(optional), 'user' ,user id
user_key_v1_re2 = re.compile("^((?P<auth2_prefix>.+)\_)?(?P<user_prefix>user)\_(?P<key>\-?[0-9]+)$")

#User key used by dedicated user cache, include two parts separated by ':': auth2_prefix(optional), user id
user_key_v2_re1 = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<key>\-?[0-9]+)$")
#User key used by dedicated user cache, include three parts separated by ':': auth2_prefix(optional), 'user' ,user id
user_key_v2_re2 = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<user_prefix>user):(?P<key>\-?[0-9]+)$")

#General data key without any prefix
data_key_v1_re = re.compile("^(?P<key>.+)$")
#General data key,include two parts separated by '_': auth2_prefix, key
data_key_v2_re = re.compile("^((?P<auth2_prefix>.+)\_)(?P<key>.+)$")
#General data key,include two parts separated by ':': auth2_prefix, key
data_key_v3_re = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<key>.+)$")


def migrate_caches(source_caches,default_cache_key_re,user_cache_key_re,session_cache_key_re,process_seq_key_re=process_seq_key_v1_re):
    """
    Migrate the cache data from source cache servers to current cache servers
    Only support memcached and redis
    """
    expired_keys = []
    unrecognized_keys = []
    session_keys = 0
    user_keys = 0
    data_keys = 0
    process_seq_keys = 0

    cacheid = 0
    for source_cache in source_caches:
        cachename = "__sourcecache{}".format(cacheid)
        cacheid += 1
        cache_server_client = CacheServerClient.create_server_client(cachename,source_cache)
        try:
            for cachekey,value,expireat in cache_server_client.items():
                if expireat and expireat < timezone.now():
                    #key is expired, ignore
                    expired_keys.append("{}={}, expireat:{}".format(cachekey,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
                    continue
                m = session_cache_key_re.search(cachekey)
                if m:
                    #session key
                    key = m.group("key")
                    _save_session(key,value,expireat)
                    session_keys += 1
                    continue
                m = user_cache_key_re.search(cachekey)
                if m:
                    #user key
                    key = m.group("key")
                    _save_user(key,value,expireat)
                    user_keys += 1
                    continue
                m =  process_seq_key_re.search(cachekey)
                if m:
                    #process seq key
                    key = m.group("key")
                    _save_process_seq(key,value,expireat)
                    process_seq_keys += 1
                    continue
                m = default_cache_key_re.search(cachekey)
                if m:
                    #general data key
                    key = m.group("key")
                    _save_data(key,value,expireat)
                    data_keys += 1
                    continue
                unrecognized_keys.append("{}={}, expireat:{}".format(cachekey,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
        finally:
            cache_server_client.close()

    print("""Migrated Cached Data:
    Migrated Session Keys     : {}
    Migrated User Keys        : {}
    Migrated Data Keys        : {}
    Migrated Process Seq Keys : {}
""".format(session_keys,user_keys,data_keys,process_seq_keys))
    if expired_keys:
        print("    =========================================================================")
        print("    Expired Keys")
        for key in expired_keys:
            print("        {}".format(key))

    if unrecognized_keys:
        print("    =========================================================================")
        print("    Unrecognized Keys")
        for key in unrecognized_keys:
            print("        {}".format(key))

def export_caches(source_caches,
    default_cache_key_re ,
    user_cache_key_re ,
    session_cache_key_re ,
    exported_dir="./cached_data",
    process_seq_key_re =  process_seq_key_v1_re
):
    """
    Export cache data from source cache servers to file system; if source cache servers is empty, use current cache servers as the source servers
    Only support memcached and redis
    """
    if not source_caches:
        source_caches = []
        if settings.CACHE_SERVER:
            source_caches.append(settings.CACHE_SERVER)
        if settings.CACHE_USER_SERVER:
            for s in settings.CACHE_USER_SERVER:
                if s not in source_caches:
                    source_caches.append(s)
        if settings.CACHE_SESSION_SERVER:
            for s in settings.CACHE_SESSION_SERVER:
                if s not in source_caches:
                    source_caches.append(s)

    print("Source caches = {}".format(source_caches))

    unrecognized_keys = []
    session_keys = 0
    user_keys = 0
    data_keys = 0
    process_seq_keys = 0

    #prepare the file system cache to store the cached data
    if os.path.exists(exported_dir):
        raise Exception("Exported folder{} already exists".format(exported_dir))
    os.makedirs(exported_dir,exist_ok=True)
    keys_file = os.path.join(exported_dir,"cached_keys.json")

    session_cache_dir = os.path.join(exported_dir,"session")
    os.mkdir(session_cache_dir)

    user_cache_dir = os.path.join(exported_dir,"user")
    os.mkdir(user_cache_dir)

    data_cache_dir = os.path.join(exported_dir,"data")
    os.mkdir(data_cache_dir)
 
    settings.CACHES["__exported_session"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': session_cache_dir,
    }
    settings.CACHES["__exported_user"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': user_cache_dir,
    }
    settings.CACHES["__exported_data"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': data_cache_dir,
    }
    session_cache = _create_cache("__exported_session")
    user_cache = _create_cache("__exported_user")
    data_cache = _create_cache("__exported_data")
 
    with open(keys_file,'wt') as f:
        cacheid = 0
        for source_cache in source_caches:
            cachename = "__sourcecache{}".format(cacheid)
            cacheid += 1
            cache_server_client = CacheServerClient.create_server_client(cachename,source_cache)
            try:
                for cachekey,value,expireat in cache_server_client.items():
                    m = session_cache_key_re.search(cachekey)
                    if m:
                        f.write(json.dumps(["session",m.groupdict(),expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None]))
                        f.write("\n")
                        session_cache.set(m.group("key"),value,timeout=None)
                        session_keys += 1
                        continue
                    m = user_cache_key_re.search(cachekey)
                    if m:
                        f.write(json.dumps(["user",m.groupdict(),expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None]))
                        f.write("\n")
                        user_cache.set(m.group("key"),value,timeout=None)
                        user_keys += 1
                        continue
                    m =  process_seq_key_re.search(cachekey)
                    if m:
                        f.write(json.dumps(["process_seq",m.groupdict(),expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None]))
                        f.write("\n")
                        session_cache.set(m.group("key"),value,timeout=None)
                        process_seq_keys += 1
                        continue
                    m = default_cache_key_re.search(cachekey)
                    if m:
                        f.write(json.dumps(["data",m.groupdict(),expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None]))
                        f.write("\n")
                        data_cache.set(m.group("key"),value,timeout=None)
                        data_keys += 1
                        continue
                    unrecognized_keys.append("{}={}, expireat:{}".format(cachekey,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
            finally:
                cache_server_client.close()


    print("""Exported Cached Data:
    Exported Session Keys     : {}
    Exported User Keys        : {}
    Exported Data Keys        : {}
    Exported Process Seq Keys : {}
""".format(session_keys,user_keys,data_keys,process_seq_keys))
    if unrecognized_keys:
        print("    =========================================================================")
        print("    Unrecognized Keys")
        for key in unrecognized_keys:
            print("        {}".format(key))

def import_caches(import_dir="./cached_data"):
    """
    Import the cached data from file system to current cache servers
    """
    keys_file = os.path.join(import_dir,"cached_keys.json")

    session_cache_dir = os.path.join(import_dir,"session")

    user_cache_dir = os.path.join(import_dir,"user")

    data_cache_dir = os.path.join(import_dir,"data")
 
    settings.CACHES["__import_session"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': session_cache_dir,
    }
    settings.CACHES["__import_user"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': user_cache_dir,
    }
    settings.CACHES["__import_data"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': data_cache_dir,
    }
    session_cache = _create_cache("__import_session")
    user_cache = _create_cache("__import_user")
    data_cache = _create_cache("__import_data")
 
    expired_keys = []
    session_keys = 0
    user_keys = 0
    data_keys = 0
    process_seq_keys = 0

    with open(keys_file,'rt') as f:
        data = f.readline()
        while data:
            data = data.strip()
            if data:
                datatype,cachekey,expireat = json.loads(data)
                expireat =  timezone.make_aware(datetime.strptime(expireat,"%Y-%m-%d %H:%M:%S.%f")) if expireat else None
                if expireat and expireat < timezone.now():
                    expired_keys.append("{}={}, expireat".format(cachekey,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f")))
                    continue
                value = None
                if datatype == "session":
                    value = session_cache.get(cachekey["key"])
                    _save_session(cachekey["key"],value,expireat)
                    session_keys += 1
                elif datatype == "user":
                    value = user_cache.get(cachekey["key"])
                    _save_user(cachekey["key"],value,expireat)
                    user_keys += 1
                elif datatype == "data":
                    value = data_cache.get(cachekey["key"])
                    _save_data(cachekey["key"],value,expireat)
                    data_keys += 1
                elif datatype == "process_seq":
                    value = session_cache.get(cachekey["key"])
                    _save_process_seq(cachekey["key"],value,expireat)
                    process_seq_keys += 1

                print("{} : {}={}".format(datatype,cachekey["key"],value))
            data = f.readline()


    print("""Imported Cache Data:
    Imported Session Keys     : {}
    Imported User Keys        : {}
    Imported Data Keys        : {}
    Imported Process Seq Keys : {}
""".format(session_keys,user_keys,data_keys,process_seq_keys))
    if expired_keys:
        print("    =========================================================================")
        print("    Expired Keys")
        for key in expired_keys:
            print("        {}".format(key))


def _save_session(key,value,expireat):
    _save(sessionstore._get_cache(key),sessionstore.get_cache_key(key),value,expireat)

def _save_user(key,value,expireat):
    userid = int(key)
    _save(get_usercache(userid),settings.GET_USER_KEY(userid),value,expireat)

def _save_data(key,value,expireat):
    _save(defaultcache,settings.GET_CACHE_KEY(key),value,expireat)

def _save_process_seq(key,value,expireat):
    _save(firstsessioncache,process_seq_key,value,expireat)

def _save(cache,key,value,expireat):
    if not expireat:
        cache.set(key,value,timeout=None)
    elif value is None:
        return
    elif timezone.now() < expireat:
        cache.set(key,value,timeout=int((expireat - timezone.now()).total_seconds()))


class CacheServerClient(object):
    seq = 0
    def __init__(self,name,server):
        self._server = server
        self._name = name
        self._conf = settings.GET_CACHE_CONF(server)
        settings.CACHES[self._name] = self._conf
        self._cache = _create_cache(self._name)

    @classmethod
    def create_server_client(cls,name,server):
        if server.lower().startswith('redis'):
            return RedisServerClient(name,server)
        else:
            return MemCachedServerClient(name,server)
        

    def items(self):
        pass

    def get(self,key):
        data = self._cache.get(key)
        return data

    def close(self):
        pass


class MemCachedServerClient(CacheServerClient):
    uptime_re = re.compile("^STAT\s+uptime\s+(?P<seconds>\d+)$")
    key_number_re = re.compile("^STAT\s+items\s*:\s*(?P<slab>\d+)\s*:\s*number\s+(?P<keys>\d+)$")
    key_row_re = re.compile("^ITEM (?P<key>\S+)\s+\[\d+\s+b\s*;\s*(?P<expireat>\d+)\s+s]$")
    def __init__(self,name,server):
        super().__init__(name,server)
        self._host,self._port = server.split(":")
        self._port = int(self._port)
        self._client = telnetlib.Telnet(self._host,self._port)
        self._server = server
        self._uptime = None
        for row in self.send_command('stats').split("\n".encode('ascii')):
            row = row.decode().strip()
            m =  self.uptime_re.search(row)
            if not m:
                continue
            #because minimum time unit is seconds instead of milliseconds, minus one second from the uptime secods to guarantee self._uptime is a little bitter later than the actual uptime. 
            self._uptime = timezone.now() - timedelta(seconds=(int(m.group("seconds")) - 1) )
            break

        if not self._uptime:
            raise Exception("Failed to find memcached server's uptime")
        else:
            print("Found memcached server's uptime '{}'".format(self._uptime.strftime("%Y-%m-%d %H:%M:%S.%f")))

    def send_command(self,command):
        self._client.write('{}\n'.format(command).encode('ascii'))
        try:
            data = self._client.read_until("END".encode('ascii'))
        except:
            print("Failed to decode.{}={}".format(command,data))
        return data[:-3]

    def close(self):
        if self._client:
            self._client.close()

    def items(self):
        for row in self.send_command('stats items').split("\n".encode('ascii')):
            if not row:
                continue
            row = row.decode().strip()
            m =  self.key_number_re.search(row)
            if not m:
                continue
            slab = m.group("slab")
            keys = m.group("keys")
            for keyrow in self.send_command('stats cachedump {} {}'.format(slab,keys)).split("\n".encode('ascii')):
                if not keyrow:
                    continue
                keyrow = keyrow.decode().strip()
                if not keyrow:
                    continue
                key_m =  self.key_row_re.search(keyrow)
                if not key_m:
                    raise Exception("Failed to parse row '{}'".format(keyrow))
                key = key_m.group("key")
                cache_key_m = cache_key_re.search(key)
                if not cache_key_m:
                    raise Exception("Failed to parse cache key '{}'".format(key))
                cache_key = cache_key_m.group("cachekey")
                expireat =  timezone.make_aware(datetime.fromtimestamp(int(key_m.group("expireat"))))
                if expireat < self._uptime:
                    #never expired
                    expireat = None
                value = self.get(cache_key)
                print("{} : {}={} expire at={}".format(self._server,cache_key,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
                yield (cache_key,value,expireat)

                
class RedisServerClient(CacheServerClient):
    def items(self):
        for cache_key in self._cache.iter_keys("*"):
            """
            cache_key_m = cache_key_re.search(key)
            if not cache_key_m:
                raise Exception("Failed to parse cache key '{1}' in server '{0}'".format(self._server,key))
            cache_key = cache_key_m.group("cachekey")
            """
            seconds = self._cache.ttl(cache_key)
            if seconds and seconds > 0:
                milliseconds = 0
                days = seconds / 86400
                seconds = seconds % 86400
                expireat = timezone.now() + timedelta(days=days,seconds=seconds,milliseconds=milliseconds)
            else:
                expireat = None
            value = self.get(cache_key)
            print("{} : {}={} expire at={}".format(self._server,cache_key,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
            yield (cache_key,value,expireat)

