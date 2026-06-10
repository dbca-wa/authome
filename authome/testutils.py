import subprocess
import collections
import os
import json
import signal
import time
import requests
from urllib.parse import quote_plus
import logging.config

from django.conf import settings
from django.utils import timezone
from django.utils.http import urlencode
from django.core.cache import caches

from . import  utils
from .serializers import JSONDecoder

class StartServerMixin(object):
    TESTED_SERVER = "http://127.0.0.1:{}"
    process_map = {}
    headers = {"HOST":settings.AUTH2_DOMAIN}
    cluster_headers = {"HOST":settings.AUTH2_DOMAIN,"X-LB-HASH-KEY":"dummykey"}

    default_env = {
        "CACHE_KEY_PREFIX" : "",
        "CACHE_KEY_VERSION_ENABLED" : "False",
        
        "PREVIOUS_CACHE_KEY_PREFIX" : "",
        "PREVIOUS_CACHE_KEY_VERSION_ENABLED" : "False",

        "STANDALONE_CACHE_KEY_PREFIX" : "",
        "STANDALONE_CACHE_KEY_VERSION_ENABLED" : "False"
   
    }

    @classmethod
    def disable_messages(cls):
        import urllib3
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


    @classmethod
    def unquotedcookie(cls,cookie):
        if not cookie:
            return cookie
        if cookie[0] == cookie[-1] and cookie[0] in ("'","\""):
            #cookie value is quoted by django
            return cookie[1:-1]
        else:
            return cookie



    @classmethod
    def start_auth2_server(cls,servername,port,auth2_env=None,start=True):
        if servername in cls.process_map:
            raise Exception("Server({}) is already running".format(servername))
        if not start:
            cls.process_map[servername] = (None,port)
            return

        auth2_env = " && ".join("export {0}=\"{1}\"".format(k,(auth2_env or {}).get(k,cls.default_env.get(k))) for k,v in cls.default_env.items())
          
        command = "/bin/bash -c 'set -a && export PORT={2} && source {0}/.env.{1} && {3} && uv run python manage.py runserver 0.0.0.0:{2}'".format(settings.BASE_DIR,servername,port,auth2_env) 
        print("Start auth2 server({}):{}".format(servername,command))
        cls.process_map[servername] = (subprocess.Popen(command,shell=True,preexec_fn=os.setsid,stdout=subprocess.PIPE),port)
        expired = 60
        while (True):
            try:
                res = requests.get(cls.get_healthcheck_url(servername),headers=cls.cluster_headers,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                break
            except Exception as ex:
                expired -= 1
                if expired > 0:
                    #print("{} : Server({}) is not ready.{}".format(utils.format_datetime(timezone.localtime()),servername,str(ex)))
                    time.sleep(1)
                else:
                    raise Exception("{} : Failed to start server({}).{}".format(utils.format_datetime(timezone.localtime()),servername,str(ex)))
                

    @classmethod
    def shutdown_auth2_server(cls,servername="standalone"):
        if servername in cls.process_map:
            if  cls.process_map[servername][0] is None:
                return
            print("shutdown auth2 server({})".format(servername))
            os.killpg(os.getpgid(cls.process_map[servername][0].pid), signal.SIGTERM)
            del cls.process_map[servername]
            time.sleep(1)
        
    @classmethod
    def shutdown_all_auth2_servers(cls):
        for servername,server in cls.process_map.items():
            if server[0] is None:
                continue
            print("shutdown auth2 server({})".format(servername))
            os.killpg(os.getpgid(server[0].pid), signal.SIGTERM)
            time.sleep(1)

        cls.process_map.clear()

    @classmethod
    def get_baseurl(cls,servername="standalone"):
        return cls.TESTED_SERVER.format(cls.process_map[servername][1] if servername in cls.process_map else "8080")

    @classmethod
    def get_profile_url(cls,servername="standalone"):
        url =  "{}/sso/profile".format(cls.get_baseurl(servername))
        return url

    @classmethod
    def get_auth_url(cls,servername="standalone"):
        url =  "{}/sso/auth".format(cls.get_baseurl(servername))
        return url

    @classmethod
    def get_auth_optional_url(cls,servername="standalone"):
        url =  "{}/sso/auth_optional".format(cls.get_baseurl(servername))
        return url

    @classmethod
    def get_basicauth_url(cls,servername="standalone"):
        url =  "{}/sso/auth_basic".format(cls.get_baseurl(servername))
        return url

    @classmethod
    def get_basicauth_optional_url(cls,servername="standalone"):
        url =  "{}/sso/auth_basic_optional".format(cls.get_baseurl(servername))
        return url

    @classmethod
    def get_login_user_url(cls,user,enabletoken=True,refreshtoken=False,servername="standalone"):
        return "{}/test/login_user?user={}&enabletoken={}&refreshtoken={}".format(cls.get_baseurl(servername),user,enabletoken,refreshtoken)

    @classmethod
    def get_delete_offline_clusters_url(cls,servername="standalone"):
        return "{}/test/deleteofflineclusters".format(cls.get_baseurl(servername))

    @classmethod
    def get_logout_url(cls,servername="standalone"):
        return "{}/sso/auth_logout".format(cls.get_baseurl(servername))

    @classmethod
    def get_healthcheck_url(cls,servername="standalone"):
        return "{}/healthcheck".format(cls.get_baseurl(servername))

    @classmethod
    def get_absolute_url(cls,url,servername="standalone"):
        return "{}{}".format(cls.get_baseurl(servername),url)

    @classmethod
    def get_save_trafficdata_url(cls,servername="standalone"):
        return "{}/test/trafficdata/save".format(cls.get_baseurl(servername))

    @classmethod
    def get_flush_trafficdata_url(cls,servername="standalone"):
        return "{}/test/trafficdata/flush".format(cls.get_baseurl(servername))

    @classmethod
    def get_update_model_url(cls,modelname,servername="standalone"):
        return "{}/test/model/{}/update".format(cls.get_baseurl(servername),modelname)

    @classmethod
    def get_delete_model_url(cls,modelname,servername="standalone"):
        return "{}/test/model/{}/delete".format(cls.get_baseurl(servername),modelname)

    @classmethod
    def get_refresh_modelcache_url(cls,modelname,servername="standalone"):
        return "{}/test/model/{}/refreshcache".format(cls.get_baseurl(servername),modelname)

    def get_settings(self,names,servername="standalone"):
        """
        Return session data if found, otherwise return None
        """
        if isinstance(names,(list,tuple)):
            namestr = ",".join(names)
        else:
            namestr = names
            names = namestr.split(",")

        res = requests.get("{}?names={}".format(self.get_absolute_url("/test/settings/get",servername),namestr),headers=self.cluster_headers,verify=settings.SSL_VERIFY)
        res.raise_for_status()
        data = res.json()
        if len(names) == 1:
            return data.get(names[0])
        else:
            return [data.get(name) for name in names]

    def get_session_data(self,session_cookie,servername="standalone",exist=True):
        """
        Return session data if found, otherwise return None
        """
        if session_cookie[0] == session_cookie[-1] and session_cookie[0] in ("'","\""):
            #session cookie is quoted by django
            session_cookie = session_cookie[1:-1]
        res = requests.get("{}?{}".format(self.get_absolute_url("/test/session/get",servername),urlencode({"session":session_cookie})),headers=self.cluster_headers,verify=settings.SSL_VERIFY)
        if exist:
            self.assertNotEqual(res.status_code,404,"The session({1}) doesn't exist in auth2 server '{0}'".format(servername,session_cookie))
            res.raise_for_status()
            data = res.json()
            return (data["session"],data["ttl"])
        else:
            self.assertEqual(res.status_code,404,"The session({1}) doesn't exist in auth2 server '{0}'".format(servername,session_cookie))
            return None

    def save_traffic_data(self,authdata,session_cookie,servername="standalone"):
        """
        Save and return the traffic data
        """
        res = requests.get("{}?{}".format(self.get_save_trafficdata_url(servername),urlencode({"session":session_cookie})),headers=self.cluster_headers,verify=settings.SSL_VERIFY,auth=authdata)
        res.raise_for_status()
        return json.loads(res.text,cls=JSONDecoder)["data"]

    def flush_traffic_data(self,authdata,session_cookie,servername="standalone"):
        """
        Flush the traffic data to redis
        """
        res = requests.get("{}?{}".format(self.get_flush_trafficdata_url(servername),urlencode({"session":session_cookie})),headers=self.cluster_headers,verify=settings.SSL_VERIFY,auth=authdata)
        res.raise_for_status()
        data = json.loads(res.text,cls=JSONDecoder)
        if data["flushed"]:
            print("Flush the data to redis for server '{}'.".format(data["server"]))
            return True
        else:
            return False


    def is_session_deleted(self,session_cookie,servername="standalone"):
        print("Check whether session is deleted from the server({}) or not".format(servername))
        return self.get_session_data(session_cookie,servername=servername,exist=False) is None

    def get_cluster_session_cookie(self,clusterid,session_cookie,lb_hash_key=None):
        values = session_cookie.split("|")
        if len(values) == 1:
            if not lb_hash_key:
                raise Exception("lb_hash_key is missing")
            session_key = session_cookie
        else:
            lb_hash_key,original_clusterid,signature,session_key = values

        sig = utils.sign_session_cookie(lb_hash_key,clusterid,session_key,settings.SECRET_KEY)
        return "{}|{}|{}|{}".format(lb_hash_key,clusterid,signature,session_key)



def set_process_logconfig(logfile:str):
    loggingconfig = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'default': {'format': '%(asctime)s %(levelname)-8s %(name)-12s %(message)s'},
            'verbose': {'format': '%(asctime)s %(levelname)-8s %(message)s'},
        },
        'handlers': {
            'default': {
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': logfile,
                'maxBytes': 4194304,  # 5MB
                'backupCount': 5,
                'formatter': 'default',
            }
        },
        'loggers': {
            'django': {
                'handlers': ['default'],
                'propagate': True,
            },
            'django.request': {
                'handlers': ['default'],
                'level': 'WARNING',
                'propagate': False,
            },
            'authome': {
                'handlers': ['default'],
                'level': settings.LOGLEVEL,
            },
        }
    }
    logging.config.dictConfig(loggingconfig)

class RedisClusterTestCaseMixin(object):
    """
    Test redis cluster cache
    Required test env: Redis cluster with 3 groups, each group has one master server and one slave server
    """
    TEST_REDISCLUSTER_CACHE = utils.env("TEST_REDISCLUSTER_CACHE",default="default")
    TEST_REDISCLUSTER_NODE_TIMEOUT = utils.env("TEST_REDISCLUSTER_NODE_TIMEOUT",15000) #milliseconds


    nodes = None
    nodeids = None
    #redis cluster groups, each group is a list which contain the group node
    groups = None
    #map between node and (group, the number of the nodes in the group)
    groupmap = None

    @classmethod
    def get_cluster_metadata(cls,start_all_server=False,print_log=False):
        cls._cache = caches[cls.TEST_REDISCLUSTER_CACHE]
        cls._redis_client = cls._cache.redis_client

        cluster_nodes = 0

        for group in cls._redis_client.clustergroups:
            for nodename in group:
                cluster_nodes += 1
                if start_all_server:
                    cls.start_redisserver(nodename,start=True)

        nodes = collections.OrderedDict()
        nodeids = collections.OrderedDict()
        groups = []
        groupmap = collections.OrderedDict()

        #redis cluster groups, each group is a list which contain the group node
        #Get the cluster nodes
        while True:
            clustermetadata = cls._redis_client.cluster_nodes()
            if start_all_server:
                if cluster_nodes != len(clustermetadata) or any( ("fail" in nodemetadata["flags"] or not nodemetadata["connected"]) for nodemetadata in clustermetadata.values()):
                    time.sleep(1)
                    continue
            break
        #populate the nodes map between node name and (node id, master flag, slaves or master node)
        for nodename,nodemetadata in clustermetadata.items():
                nodeids[nodemetadata["node_id"]] = nodename
                if "fail" in nodemetadata["flags"] or not nodemetadata["connected"]:
                    nodes[nodename] = {"id":nodemetadata["node_id"],"is_master":None}
                elif "master" in nodemetadata["flags"]:
                    nodes[nodename] = {"id":nodemetadata["node_id"],"is_master":True, "slaves":[]}
                else:
                    nodes[nodename] = {"id":nodemetadata["node_id"],"is_master":False, "master":None}

        #populate the cluster group list with (node name,master?,running?), master node should be the first node.
        #populate the cluster group map between node name and (cluster group , index in the cluster groups)
        for clustergroup in cls._redis_client.clustergroups:
            group = []
            groups.append(group)
            groupindex = len(groups) - 1
            for nodename in clustergroup:
                #find/create the group in groups and groupmap
                groupmap[nodename] = [group,groupindex]
                    
                if nodename in clustermetadata:
                    #already added into 
                    nodemetadata = clustermetadata[nodename]
                    if "master" in nodemetadata["flags"] and "fail" not in nodemetadata["flags"] and nodemetadata["connected"]:
                        group.insert(0,[nodename,True,True])
                    elif "master" not in nodemetadata["flags"] and "master_id" in nodemetadata and "fail" not in nodemetadata["flags"] and nodemetadata["connected"]:
                        group.append([nodename,False,True])
                        if nodes[nodeids[nodemetadata["master_id"]]]["is_master"]:
                            nodes[nodeids[nodemetadata["master_id"]]]["slaves"].append(nodename)
                        nodes[nodename]["master"] = nodeids[nodemetadata["master_id"]]
                    else:
                        group.append([nodename,False,False])
                else:
                    group.append([nodename,False,False])
        if print_log:
            cls.print_metadata(nodeids,nodes,groups,groupmap)

        return (nodeids,nodes,groups,groupmap)

    
    @classmethod
    def print_metadata(cls,nodeids=None,nodes=None,groups=None,groupmap=None):
        print("==============Print the redis cluster metadata====================")
        print("============redis Cluster Nodeids===================")
        print(json.dumps(nodeids or cls.nodeids,indent=4))
        print("============redis Cluster Nodes===================")
        print(json.dumps(nodes or cls.nodes,indent=4))
        print("============redis Cluster Groups===================")
        print(json.dumps(groups or cls.groups,indent=4))
        print("============redis Cluster map between node and group===================")
        print(json.dumps(groupmap or cls.groupmap,indent=4))
        print("---------------------------------------------------------------------")

    @classmethod
    def start_redisserver(cls,nodename:str,start:bool=True):
        """
        Start/stop redis server
        nodename: host:port
        """
        if start:
            result = subprocess.run(["/home/rockyc/projects/commonservice/start_redisserver",nodename.split(':')[1]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,text=True,bufsize=0)
            if result.returncode != 0:
                raise Exception("Failed to start redis server({}).".format(nodename))
        else:
            result = subprocess.run(["/home/rockyc/projects/commonservice/stop_redisserver",nodename.split(':')[1]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,text=True,bufsize=0)
            if result.returncode != 0:
                raise Exception("Failed to stop redis server({}).".format(nodename))
