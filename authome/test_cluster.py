import subprocess
import os
import signal
import requests
import time

from django.conf import settings
from django.test import TestCase
from django.utils import timezone

from . import utils


class ClusterTestCase(TestCase):
    process_map = {}
    headers = {"HOST":settings. AUTH2_DOMAIN}
    cluster_headers = {"HOST":settings. AUTH2_DOMAIN,"X-hash-key":"dummy key"}

    def get_healthcheck_url(self,servername):
        return "http://127.0.0.1:{}/healthcheck".format(self.process_map[servername][1])

    def get_profile_url(self,servername):
        return "http://127.0.0.1:{}/sso/profile".format(self.process_map[servername][1])

    def get_login_user_url(self,servername,user):
        return "http://127.0.0.1:{}/test/login_user?user={}".format(self.process_map[servername][1],user)

    def start_auth2_server(self,servername,port):
        if servername in self.process_map:
            raise Exception("Server({}) is already running".format(servername))
        self.process_map[servername] = (subprocess.Popen(["./start_auth2 {} {}".format(port,servername)],shell=True,preexec_fn=os.setsid,stdout=subprocess.PIPE),port)
        expired = 60
        while (True):
            try:
                res = requests.get(self.get_healthcheck_url(servername),headers=self.cluster_headers)
                res.raise_for_status()
                break
            except Exception as ex:
                expired -= 1
                if expired > 0:
                    print("{} : Server({}) is not ready.{}".format(utils.format_datetime(timezone.localtime()),servername,str(ex)))
                    time.sleep(1)
                else:
                    raise("{} : Failed to start server({}).{}".format(utils.format_datetime(timezone.localtime()),servername,str(ex)))
                

    def shutdown_auth2_server(self,servername="standalone"):
        if servername in self.process_map:
            print("shutdown auth2 server({})".format(servername))
            os.killpg(os.getpgid(self.process_map[servername][0].pid), signal.SIGTERM)
            del self.process_map[servername]
            time.sleep(1)
        
    def shutdown_all_auth2_servers(self):
        for servername,server in self.process_map.items():
            print("shutdown auth2 server({})".format(servername))
            os.killpg(os.getpgid(server[0].pid), signal.SIGTERM)
            time.sleep(1)

        self.process_map.clear()
        
    def test_migrate_to_default_cluster(self):
        try:
            #login to a standalone server first
            self.start_auth2_server("standalone",18060)
            res = requests.get(self.get_login_user_url("standalone","test_user01@test.com"),headers=self.headers)
            res.raise_for_status()
            session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
            res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
            res.raise_for_status()
            user_profile = res.json()
            self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in")
            print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
            self.shutdown_auth2_server("standalone")

            #migrate to cluster server
            self.start_auth2_server("auth01",18061)
            lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
            self.cluster_headers["X-hash-key"] = lb_hash_key
            res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
            res.raise_for_status()
            cluster_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
            returned_lb_hash_key,auth2_cluster,session_key = cluster_session_cookie.split("|",2)
            self.assertEqual(lb_hash_key,returned_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-hash-key'")
            self.assertEqual(auth2_cluster,"AUTH2_01",msg="Auth2 clusterid({}) should be 'AUTH2_01'".format(auth2_cluster))
            self.assertEqual(session_cookie,session_key[:-2-16] + session_key[-2:],msg="Cluster session id should be populated from original session key")
            user_profile2 = res.json()
            print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,cluster_session_cookie))
            print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))







        finally:
            self.shutdown_all_auth2_servers()

        pass
