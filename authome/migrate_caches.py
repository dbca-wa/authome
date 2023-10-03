import telnetlib
import re
import json
import os
import urllib
import base64
from datetime import datetime,timedelta


from django.conf import settings
from django.utils import timezone
from django.core.cache.backends.memcached import MemcachedCache
from django.core.cache import caches
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY

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
session_key_v2_re = re.compile("^((?P<auth2_prefix>[a-zA-Z0-9_\-]+)\-)?(?P<session_prefix>session)\-(?P<key>[a-z0-9\-]+)$")
#auth2 session cache key , include three parts separated by ':': auth2_prefix(Optional), 'session', session key(process_prefix plus random generated key)
session_key_v3_re = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<session_prefix>session):(?P<key>[a-z0-9\-]+)$")

#User key used by dedicated user cache, include two parts separated by '-': auth2_prefix(optional), user id
user_key_v1_re1 = re.compile("^((?P<auth2_prefix>.+)\_)?(?P<key>\-?[0-9]+)$")
#User key used by dedicated user cache, include three parts separated by '-': auth2_prefix(optional), 'user' ,user id
user_key_v1_re2 = re.compile("^((?P<auth2_prefix>.+)\_)?(?P<user_prefix>user)\_(?P<key>\-?[0-9]+)$")

#User key used by dedicated user cache, include two parts separated by ':': auth2_prefix(optional), user id
user_key_v2_re1 = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<key>\-?[0-9]+)$")
#User key used by dedicated user cache, include three parts separated by ':': auth2_prefix(optional), 'user' ,user id
user_key_v2_re2 = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<user_prefix>user):(?P<key>\-?[0-9]+)$")

#User token key used by dedicated user cache, include two parts separated by ':': auth2_prefix(optional), user id
usertoken_key_v2_re1 = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<key>\-?[0-9]+)$")
#User token key used by dedicated user cache, include three parts separated by ':': auth2_prefix(optional), 'user' ,user id
usertoken_key_v2_re2 = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<token_prefix>token):(?P<key>\-?[0-9]+)$")

#General data key without any prefix
data_key_v1_re = re.compile("^(?P<key>.+)$")
#General data key,include two parts separated by '_': auth2_prefix, key
data_key_v2_re = re.compile("^((?P<auth2_prefix>.+)\_)(?P<key>.+)$")
#General data key,include two parts separated by ':': auth2_prefix, key
data_key_v3_re = re.compile("^((?P<auth2_prefix>[^:]+):)?(?P<key>.+)$")

def _create_cache(name):
    caches[name] = caches.create_connection(name)
    return caches[name]


def migrate_caches(source_caches,session_cache_key_re,default_cache_key_re=None,user_cache_key_re=None,usertoken_cache_key_re=None,process_seq_key_re=process_seq_key_v1_re):
    """
    Migrate the cache data from source cache servers to current cache servers
    Only support memcached and redis
    """
    empty_keys = []
    expired_keys = []
    ignored_keys = 0
    session_keys = 0
    guest_session_keys = 0
    user_keys = 0
    usertoken_keys = 0
    data_keys = 0
    process_seq_keys = 0
    processed_keys = 0

    cacheid = 0
    for source_cache in source_caches:
        cachename = "__sourcecache{}".format(cacheid)
        cacheid += 1
        cache_server_client = CacheServerClient.create_server_client(cachename,source_cache)
        try:
            for cachekey,value,expireat in cache_server_client.items():
                try:
                    print("key="+cachekey)
                    if expireat and expireat < timezone.localtime():
                        #key is expired, ignore
                        expired_keys.append("{}={}, expireat:{}".format(cachekey,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
                        continue
    
                    if not value:
                        empty_keys.append("{} expireat:{}".format(cachekey,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
                        continue
    
                    m = session_cache_key_re.search(cachekey) if session_cache_key_re else None
                    if m:
                        #session key
                        key = m.group("key")
                        if value.get(USER_SESSION_KEY):
                            _save_session(key,value,expireat)
                            session_keys += 1
                        else:
                            guest_session_keys += 1

                        continue
                    m = user_cache_key_re.search(cachekey) if user_cache_key_re else None
                    if m:
                        #user key
                        key = m.group("key")
                        _save_user(key,value,expireat)
                        user_keys += 1
                        continue
                    m = usertoken_cache_key_re.search(cachekey) if usertoken_cache_key_re else None
                    if m:
                        #user key
                        key = m.group("key")
                        _save_usertoken(key,value,expireat)
                        usertoken_keys += 1
                        continue
                    m =  process_seq_key_re.search(cachekey) if process_seq_key_re else None
                    if m:
                        #process seq key
                        key = m.group("key")
                        _save_process_seq(key,value,expireat)
                        process_seq_keys += 1
                        continue
                    m = default_cache_key_re.search(cachekey) if default_cache_key_re else None
                    if m:
                        #general data key
                        key = m.group("key")
                        _save_data(key,value,expireat)
                        data_keys += 1
                        continue
                    ignored_keys += 1
                finally:
                    processed_keys += 1
                    if processed_keys % 1000 == 0:
                        print("Processed {} keys, Session Keys : {} , Guest Session Keys : {} ,  User Keys : {} ,  User Token Keys : {} , Process Seq Keys : {} , Data Keys : {}".format(processed_keys,session_keys,guest_session_keys,user_keys,usertoken_keys,process_seq_keys,data_keys))
        finally:
            cache_server_client.close()

    print("""Migrated Cached Data:
    Total Migrated Keys        : {}
    Migrated Session Keys      : {}
    Ignored Guest Session Keys : {}
    Migrated User Keys         : {}
    Migrated User Token Keys   : {}
    Migrated Data Keys         : {}
    Migrated Process Seq Keys  : {}
    Ignored Keys               : {}  
""".format(processed_keys,session_keys,guest_session_keys,user_keys,usertoken_keys,data_keys,process_seq_keys,ignored_keys))
    if expired_keys:
        print("    =========================================================================")
        print("    Expired Keys")
        for key in expired_keys:
            print("        {}".format(key))

    if empty_keys:
        print("    =========================================================================")
        print("    Empty Keys")
        for key in empty_keys:
            print("        {}".format(key))

def export_caches(source_caches,
    session_cache_key_re ,
    default_cache_key_re = None ,
    user_cache_key_re = None ,
    usertoken_cache_key_re = None ,
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

    ignored_keys = 0
    session_keys = 0
    guest_session_keys = 0
    user_keys = 0
    usertoken_keys = 0
    data_keys = 0
    process_seq_keys = 0
    empty_keys = []

    #prepare the file system cache to store the cached data
    if os.path.exists(exported_dir):
        raise Exception("Exported folder{} already exists".format(exported_dir))
    os.makedirs(exported_dir,exist_ok=True)
    keys_file = os.path.join(exported_dir,"cached_keys.json")

    session_cache_dir = os.path.join(exported_dir,"session")
    os.mkdir(session_cache_dir)

    user_cache_dir = os.path.join(exported_dir,"user")
    os.mkdir(user_cache_dir)

    usertoken_cache_dir = os.path.join(exported_dir,"usertoken")
    os.mkdir(usertoken_cache_dir)

    data_cache_dir = os.path.join(exported_dir,"data")
    os.mkdir(data_cache_dir)
 
    settings.CACHES["__exported_session"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': session_cache_dir,
        "OPTIONS":{
            "MAX_ENTRIES":40000000
        }
    }
    settings.CACHES["__exported_user"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': user_cache_dir,
        "OPTIONS":{
            "MAX_ENTRIES":40000000
        }
    }
    settings.CACHES["__exported_usertoken"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': usertoken_cache_dir,
        "OPTIONS":{
            "MAX_ENTRIES":40000000
        }
    }
    settings.CACHES["__exported_data"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': data_cache_dir,
        "OPTIONS":{
            "MAX_ENTRIES":40000000
        }
    }
    session_cache = _create_cache("__exported_session")
    user_cache = _create_cache("__exported_user")
    usertoken_cache = _create_cache("__exported_usertoken")
    data_cache = _create_cache("__exported_data")

    processed_keys = 0
 
    with open(keys_file,'wt') as f:
        cacheid = 0
        for source_cache in source_caches:
            cachename = "__sourcecache{}".format(cacheid)
            cacheid += 1
            cache_server_client = CacheServerClient.create_server_client(cachename,source_cache)
            try:
                for cachekey,value,expireat in cache_server_client.items():
                    try:
                        if not value:
                            empty_keys.append("{} expireat:{}".format(cachekey,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
                            continue
    
                        m = session_cache_key_re.search(cachekey) if session_cache_key_re else None
                        if m:
                            if value.get(USER_SESSION_KEY):
                                f.write(json.dumps(["session",m.groupdict(),expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None]))
                                f.write("\n")
                                if not session_cache.add(m.group("key"),value,timeout=None):
                                    raise Exception("Failed to save the key({}) to file system cache.".format(m.group("key")))
                                session_keys += 1
                            else:
                                #ignore the guest session
                                guest_session_keys += 1

                            continue

                        m = user_cache_key_re.search(cachekey) if user_cache_key_re else None
                        if m:
                            f.write(json.dumps(["user",m.groupdict(),expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None]))
                            f.write("\n")
                            if not user_cache.add(m.group("key"),value,timeout=None):
                                raise Exception("Failed to save the key({}) to file system cache.".format(m.group("key")))
                            user_keys += 1
                            continue
                        m = usertoken_cache_key_re.search(cachekey) if usertoken_cache_key_re else None
                        if m:
                            f.write(json.dumps(["usertoken",m.groupdict(),expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None]))
                            f.write("\n")
                            if not usertoken_cache.add(m.group("key"),value,timeout=None):
                                raise Exception("Failed to save the key({}) to file system cache.".format(m.group("key")))
                            usertoken_keys += 1
                            continue
                        m =  process_seq_key_re.search(cachekey) if process_seq_key_re else None
                        if m:
                            f.write(json.dumps(["process_seq",m.groupdict(),expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None]))
                            f.write("\n")
                            if not session_cache.add(m.group("key"),value,timeout=None):
                                raise Exception("Failed to save the key({}) to file system cache.".format(m.group("key")))
                            process_seq_keys += 1
                            continue
                        m = default_cache_key_re.search(cachekey) if default_cche_key_re else None
                        if m:
                            f.write(json.dumps(["data",m.groupdict(),expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None]))
                            f.write("\n")
                            if not data_cache.add(m.group("key"),value,timeout=None):
                                raise Exception("Failed to save the key({}) to file system cache.".format(m.group("key")))
                            data_keys += 1
                            continue
                        ignored_keys += 1
                    finally:
                        processed_keys += 1
                        if processed_keys % 1000 == 0:
                            print("Processed {} keys, Session Keys : {} , Guest Session Keys : {} ,  User Keys : {} , User Token Keys : {} , Process Seq Keys : {} , Data Keys : {}".format(processed_keys,session_keys,guest_session_keys,user_keys,usertoken_keys,process_seq_keys,data_keys))
            finally:
                cache_server_client.close()


    print("""Exported Cached Data:
    Total Exported Keys        : {}
    Exported Session Keys      : {}
    Ignored Guest Session Keys : {}
    Exported User Keys         : {}
    Exported User Token Keys   : {}
    Exported Data Keys         : {}
    Exported Process Seq Keys  : {}
    Ignored Keys               : {}
    
""".format(processed_keys,session_keys,guest_session_keys,user_keys,usertoken_keys,data_keys,process_seq_keys,ignored_keys))
    if empty_keys:
        print("    =========================================================================")
        print("    Empty Keys")
        for key in empty_keys:
            print("        {}".format(key))

def import_caches(import_dir="./cached_data"):
    """
    Import the cached data from file system to current cache servers
    """
    keys_file = os.path.join(import_dir,"cached_keys.json")

    session_cache_dir = os.path.join(import_dir,"session")

    user_cache_dir = os.path.join(import_dir,"user")

    usertoken_cache_dir = os.path.join(import_dir,"usertoken")

    data_cache_dir = os.path.join(import_dir,"data")
 
    settings.CACHES["__import_session"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': session_cache_dir,
        "OPTIONS":{
            "MAX_ENTRIES":40000000
        }
    }
    settings.CACHES["__import_user"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': user_cache_dir,
        "OPTIONS":{
            "MAX_ENTRIES":40000000
        }
    }
    settings.CACHES["__import_usertoken"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': usertoken_cache_dir,
        "OPTIONS":{
            "MAX_ENTRIES":40000000
        }
    }
    settings.CACHES["__import_data"] = {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': data_cache_dir,
        "OPTIONS":{
            "MAX_ENTRIES":40000000
        }
    }
    session_cache = _create_cache("__import_session")
    user_cache = _create_cache("__import_user")
    usertoken_cache = _create_cache("__import_usertoken")
    data_cache = _create_cache("__import_data")
 
    expired_keys = []
    session_keys = 0
    guest_session_keys = 0
    user_keys = 0
    usertoken_keys = 0
    data_keys = 0
    process_seq_keys = 0

    processed_keys = 0

    session_report= {}

    with open(keys_file,'rt') as f:
        data = f.readline()
        while data:
            data = data.strip()
            try:
                if data:
                    #print("Processing key:{}".format(data))
                    datatype,cachekey,expireat = json.loads(data)
                    expireat =  timezone.make_aware(datetime.strptime(expireat,"%Y-%m-%d %H:%M:%S.%f")) if expireat else None
                    if expireat and expireat < timezone.localtime():
                        expired_keys.append("{}={}, expireat".format(cachekey,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f")))
                        continue
                    value = None
                    if datatype == "session":
                        value = session_cache.get(cachekey["key"])
                        if value.get(USER_SESSION_KEY):
                            _save_session(cachekey["key"],value,expireat)
                            session_report[value.get(USER_SESSION_KEY)] = session_report.get(value.get(USER_SESSION_KEY),0) + 1
                            session_keys += 1
                        elif len(value.keys()) == 0:
                            session_report["EMPTY"] = session_report.get("EMPTY",0) + 1
                            guest_session_keys += 1
                        else:
                            keys = [k for k in value.keys()]
                            keys.sort()
                            keys = tuple(keys)
                            session_report[keys] = session_report.get(keys,0) + 1
                            session_report["GUEST"] = session_report.get("GUEST",0) + 1
                            guest_session_keys += 1
                    elif datatype == "user":
                        value = user_cache.get(cachekey["key"])
                        _save_user(cachekey["key"],value,expireat)
                        user_keys += 1
                    elif datatype == "usertoken":
                        value = usertoken_cache.get(cachekey["key"])
                        _save_usertoken(cachekey["key"],value,expireat)
                        usertoken_keys += 1
                    elif datatype == "data":
                        value = data_cache.get(cachekey["key"])
                        _save_data(cachekey["key"],value,expireat)
                        data_keys += 1
                    elif datatype == "process_seq":
                        value = session_cache.get(cachekey["key"])
                        _save_process_seq(cachekey["key"],value,expireat)
                        process_seq_keys += 1
    
                    #print("{} : {}={}".format(datatype,cachekey["key"],value))

            finally:
                processed_keys += 1
                if processed_keys % 1000 == 0:
                    print("Processed {} keys, Session Keys : {} , Guest Session Keys : {} ,  User Keys : {} , Process Seq Keys : {} , Data Keys : {} , Expired Keys : {}".format(processed_keys,session_keys,guest_session_keys,user_keys,process_seq_keys,data_keys,len(expired_keys)))
                data = f.readline()


    print("""Imported Cache Data:
    Total Imported Keys        : {}
    Imported Session Keys      : {}
    Ignored Guest Session Keys : {}
    Imported User Keys         : {}
    Imported User Token Keys   : {}
    Imported Data Keys         : {}
    Imported Process Seq Keys  : {}
    Imported Expired Keys      : {}
""".format(processed_keys,session_keys,guest_session_keys,user_keys,usertoken_keys,data_keys,process_seq_keys,len(expired_keys)))
    print("    =========================================================================")
    print("    Expired Session Keys : {}".format(session_keys))
    for k,v in session_report.items():
        if k in ("GUEST","EMPTY"):
            continue
        print("        User({}) : {}".format(k,v))
    print("        User(GUEST) : {}".format(session_report.get("GUEST",0)))
    print("        User(EMPTY) : {}".format(session_report.get("EMPTY",0)))

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

def _save_usertoken(key,value,expireat):
    userid = int(key)
    _save(get_usercache(userid),settings.GET_USERTOKEN_KEY(userid),value,expireat)

def _save_data(key,value,expireat):
    _save(defaultcache,key,value,expireat)

def _save_process_seq(key,value,expireat):
    _save(firstsessioncache,process_seq_key,value,expireat)

def _save(cache,key,value,expireat):
    if not expireat:
        cache.set(key,value,timeout=None)
    elif value is None:
        return
    elif timezone.localtime() < expireat:
        if not cache.add(key,value,timeout=int((expireat - timezone.localtime()).total_seconds())):
            raise Exception("Failed to save the item({}={}) to current cache server".format(key,value))


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
    version_re = re.compile("^\s*VERSION\s+(?P<version>[0-9](\.[0-9]+)*)\s*$")
    uptime_re = re.compile("^STAT\s+uptime\s+(?P<seconds>\d+)$")
    key_number_re = re.compile("^STAT\s+items\s*:\s*(?P<slab>\d+)\s*:\s*number\s+(?P<keys>\d+)$")
    key_row_re = re.compile("^ITEM (?P<key>\S+)\s+\[\d+\s+b\s*;\s*(?P<expireat>\d+)\s+s]$")
    lru_row_re = re.compile("^\s*key=(?P<key>\S+)\s+exp=(?P<expireat>-?\d+).+$")
    def __init__(self,name,server):
        super().__init__(name,server)
        self._host,self._port = server.split(":")
        self._port = int(self._port)
        self._client = telnetlib.Telnet(self._host,self._port)
        self._server = server
        self._uptime = None
        #data = self._client.read_until("END".encode('ascii'))
        data = self.send_command('version',end='XXXXX',timeout=1).decode()
        m = self.version_re.search(data)
        if not m:
            raise Exception("Can't find memcached's version")
        self._version = [int(i) for i in m.group("version").split(".")]
        print("MemCached's version is {}".format(m.group("version")))

        for row in self.send_command('stats').split("\n".encode('ascii')):
            row = row.decode().strip()
            m =  self.uptime_re.search(row)
            if not m:
                continue
            #because minimum time unit is seconds instead of milliseconds, minus one second from the uptime secods to guarantee self._uptime is a little bitter later than the actual uptime. 
            self._uptime = timezone.localtime() - timedelta(seconds=(int(m.group("seconds")) - 1) )
            break

        if not self._uptime:
            raise Exception("Failed to find memcached server's uptime")
        else:
            print("Found memcached server's uptime '{}'".format(self._uptime.strftime("%Y-%m-%d %H:%M:%S.%f")))

        if self._version[0] < 1 or (self._version[0] == 1 and (self._version[1] < 4 or (self._version[1] == 4 and self._version[2] < 31))):
            self.items = self._items_from_stats_items
        else:
            self.items = self._items_from_lru

    def send_command(self,command,client=None,end='END',timeout=2):
        client = client or self._client
        client.write('{}\n'.format(command).encode('ascii'))
        data = client.read_until(end.encode('ascii'),timeout=timeout)
        if data.endswith(end.encode('ascii')):
            return data[:-3].strip()
        else:
            return data

    def readline_from_command(self,command,client=None,end='END',timeout=2):
        client = client or self._client
        client.write('{}\n'.format(command).encode('ascii'))
        end = end.encode('ascii')
        finished = False
        while not finished:
            data = client.read_until("\n".encode('ascii'),timeout=timeout)
            if not data:
                finished = True
                break
            data = data.strip().split("\n".encode("ascii"))
            for row in data:
                row = row.strip()
                if not row:
                    continue
                if row == end:
                    finished = True
                    break
                yield row

    def close(self):
        if self._client:
            self._client.close()

    def _items_from_lru(self):
        for row in self.readline_from_command('lru_crawler metadump all',timeout=10):
            if not row:
                continue
            row = urllib.parse.unquote(row.decode().strip())
            m =  self.lru_row_re.search(row)
            if not m:
                raise Exception("Failed to parse row '{}'".format(row))
            key = m.group("key")
            cache_key_m = cache_key_re.search(key)
            if not cache_key_m:
                raise Exception("Failed to parse cache key '{}'".format(key))
            cache_key = cache_key_m.group("cachekey")
            expireat = int(m.group("expireat"))
            if expireat < 0:
                expireat = None
            else:
                expireat =  timezone.make_aware(datetime.fromtimestamp(expireat))
                if expireat < self._uptime:
                    #never expired
                    expireat = None
            value = self.get(cache_key)
            #print("{} : {}={} expire at={}".format(self._server,cache_key,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
            yield (cache_key,value,expireat)



    def _items_from_stats_items(self):
        for row in self.send_command('stats items').split("\n".encode('ascii')):
            if not row:
                continue
            row = row.decode().strip()
            m =  self.key_number_re.search(row)
            if not m:
                continue
            slab = m.group("slab")
            keys = m.group("keys")
            for keyrow in self.readline_from_command('stats cachedump {} {}'.format(slab,keys)):
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
                #print("{} : {}={} expire at={}".format(self._server,cache_key,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
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
                expireat = timezone.localtime() + timedelta(days=days,seconds=seconds,milliseconds=milliseconds)
            else:
                expireat = None
            value = self.get(cache_key)
            #print("{} : {}={} expire at={}".format(self._server,cache_key,value,expireat.strftime("%Y-%m-%d %H:%M:%S.%f") if expireat else None))
            yield (cache_key,value,expireat)

