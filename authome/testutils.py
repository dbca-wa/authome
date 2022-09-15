import subprocess
import os
import signal
import time
import requests

from django.conf import settings
from django.utils import timezone

from . import  utils

class StartServerMixin(object):
    TESTED_SERVER = "http://127.0.0.1:{}"
    process_map = {}
    headers = {"HOST":settings.AUTH2_DOMAIN}
    cluster_headers = {"HOST":settings.AUTH2_DOMAIN,"X-LB-HASH-KEY":"dummy key"}

    @classmethod
    def start_auth2_server(cls,servername,port,precommands=None):
        if servername in cls.process_map:
            raise Exception("Server({}) is already running".format(servername))
        if precommands:
            command = "{} && ./start_auth2 {} {}".format(precommands,port,servername) 
        else:
            command = "./start_auth2 {} {}".format(port,servername) 
        cls.process_map[servername] = (subprocess.Popen([command],shell=True,preexec_fn=os.setsid,stdout=subprocess.PIPE),port)
        expired = 60
        while (True):
            try:
                res = requests.get(cls.get_healthcheck_url(servername),headers=cls.cluster_headers)
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
    def get_settings(cls,names,servername="standalone"):
        """
        Return session data if found, otherwise return None
        """
        if isinstance(names,(list,tuple)):
            namestr = ",".join(names)
        else:
            namestr = names
            names = namestr.split(",")

        res = requests.get("{}?names={}".format(cls.get_absolute_url("/test/settings/get",servername),namestr),headers=cls.cluster_headers)
        res.raise_for_status()
        data = res.json()
        if len(names) == 1:
            return data.get(names[0])
        else:
            return [data.get(name) for name in names]

    @classmethod
    def get_session_data(cls,session_cookie,servername="standalone"):
        """
        Return session data if found, otherwise return None
        """
        res = requests.get("{}?session={}".format(cls.get_absolute_url("/test/session/get",servername),session_cookie),headers=cls.cluster_headers)
        if res.status_code == 404:
            return None
        else:
            res.raise_for_status()
        return res.json()

    @classmethod
    def is_session_deleted(cls,session_cookie,servername="standalone"):
        return cls.get_session_data(session_cookie,servername=servername) is None

    @classmethod
    def get_cluster_session_cookie(cls,clusterid,session_cookie,lb_hash_key=None):
        values = session_cookie.split("|")
        if len(values) == 1:
            if not lb_hash_key:
                raise Exception("lb_hash_key is missing")
            session_key = session_cookie
        else:
            lb_hash_key,original_clusterid,signature,session_key = values

        sig = utils.sign_lb_hash_key(lb_hash_key,clusterid,settings.SECRET_KEY)
        return "{}|{}|{}|{}".format(lb_hash_key,clusterid,signature,session_key)
