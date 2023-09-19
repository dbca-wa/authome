import subprocess
import os
import json
import signal
import time
import requests

from django.conf import settings
from django.utils import timezone
from django.utils.http import urlencode

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
    def clean_cookie(cls,cookie):
        if not cookie:
            return cookie
        if cookie[0] == cookie[-1] and cookie[0] in ("'","\""):
            #cookie value is quoted by django
            return cookie[1:-1]
        else:
            return cookie



    @classmethod
    def start_auth2_server(cls,servername,port,auth2_env=None):
        if servername in cls.process_map:
            raise Exception("Server({}) is already running".format(servername))
        auth2_env = " && ".join("export {0}=\"{1}\"".format(k,(auth2_env or {}).get(k,cls.default_env.get(k))) for k,v in cls.default_env.items())
          
        command = "/bin/bash -c 'set -a && export PORT={2} && source {0}/.env.{1} && {3} && poetry run python manage.py runserver 0.0.0.0:{2}'".format(settings.BASE_DIR,servername,port,auth2_env) 
        print("Start auth2 server:{}".format(command))
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
                    raise("{} : Failed to start server({}).{}".format(utils.format_datetime(timezone.localtime()),servername,str(ex)))
                

    @classmethod
    def shutdown_auth2_server(cls,servername="standalone"):
        if servername in cls.process_map:
            print("shutdown auth2 server({})".format(servername))
            os.killpg(os.getpgid(cls.process_map[servername][0].pid), signal.SIGTERM)
            del cls.process_map[servername]
            time.sleep(1)
        
    @classmethod
    def shutdown_all_auth2_servers(cls):
        for servername,server in cls.process_map.items():
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
        print("profile url = {}".format(url))
        return url

    @classmethod
    def get_login_user_url(cls,user,servername="standalone"):
        return "{}/test/login_user?user={}".format(cls.get_baseurl(servername),user)

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
        else:
            return None
        res.raise_for_status()
        return res.json()

    def save_traffic_data(self,session_cookie,servername="standalone"):
        """
        Save and return the traffic data
        """
        res = requests.get("{}?{}".format(self.get_save_trafficdata_url(servername),urlencode({"session":session_cookie})),headers=self.cluster_headers,verify=settings.SSL_VERIFY)
        res.raise_for_status()
        return json.loads(res.text,cls=JSONDecoder)["data"]

    def flush_traffic_data(self,session_cookie,servername="standalone"):
        """
        Flush the traffic data to redis
        """
        res = requests.get("{}?{}".format(self.get_flush_trafficdata_url(servername),urlencode({"session":session_cookie})),headers=self.cluster_headers,verify=settings.SSL_VERIFY)
        res.raise_for_status()
        data = json.loads(res.text,cls=JSONDecoder)
        if data["flushed"]:
            print("Flush the data to redis for server '{}'.".format(data["server"]))
            return True
        else:
            return False


    def is_session_deleted(self,session_cookie,servername="standalone"):
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
