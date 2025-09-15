import requests

from django.conf import settings
from django.test import TestCase
from django.utils import timezone

from . import utils
from . import testutils
"""
To run this test case, you should have the following resources
1. a shell script to start auth2 server './start_auth2'
2. the set of env files to start different type of auth2 server
  A. standalone: a standalone auth2 server
  B. standalone2: a standalone auth2 server whose previous session cache is the session cache of 'standalone'
  C. auth01: a default cluster auth2 server 'AUTH2_01', it has the same cache setting as auth2 server 'standalone'
  C. auth01a: a cluster auth2 server 'AUTH2_01', it's previous session cache is the session cache of auth01
  D. auth02: a cluster auth2 server 'AUTH2_02', 
  E. auth02a: a default cluster auth2 server 'AUTH2_02', it has the same cache server setting as auth2 server 'standalone2' including previous session cache
  F. auth03: a cluster auth2 server 'AUTH2_03' 
"""
RUN_CASES = -1
class ClusterTestCase(testutils.StartServerMixin,TestCase):
    @classmethod
    def setUpClass(cls):
        super(ClusterTestCase,cls).setUpClass()
        cls.disable_messages()

    def test_previous_session_cache(self):
        """
        Test the feature 'Migrate the session from previous session cache' for standalone auth2 server
        """
        print("************Begin to run test case 'test_previous_session_cache'******************************")
        index = 0
        for auth2_envs in [
            {},
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "standalone2":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone"
                }
            },
            {
                "standalone2":{
                    "CACHE_KEY_PREFIX":"standalone2"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "standalone2":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone",
                    "CACHE_KEY_PREFIX":"standalone2"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "standalone2":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth2",
                    "CACHE_KEY_PREFIX":"auth2"
                }
            },
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(auth2_envs))

            try:
                #login to a standalone server to get the standalone session cookie 
                self.start_auth2_server("standalone",18060,auth2_env=auth2_envs.get("standalone"))
                res = requests.get(self.get_login_user_url("test_user01@test.com",servername="standalone"),headers=self.headers,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                session_data,ttl = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
                print("\n")
    
                #start server 'standalone2' whose previous session cache is the session cache of server 'standalone'
                #use the session cookie to access server 'standalone2' to migrate the session to session cache of server 'standalone'
                self.start_auth2_server("standalone2",18061,auth2_env=auth2_envs.get("standalone2"))
                res = requests.get(self.get_profile_url(servername="standalone2"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                self.assertEqual(self.unquotedcookie(res.cookies.get(settings.SESSION_COOKIE_NAME)),None,msg="Session is migrated from previous session cache. and the client session cookie should not be changed, response should not return session cookie..auth2_envs={}".format(auth2_envs))
                user_profile2 = res.json()
                self.assertEqual(user_profile2["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                session_data2,ttl = self.get_session_data(session_cookie,"standalone2")
                self.assertEqual(session_data2,session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("\n".join("{}={}".format(k,v) for k,v in user_profile2.items()))
                print("\n")
    
                #session has migrated from previous cache,check whether the session in the original session cache is invalidated.
                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile3 = res.json()
                self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.auth2_envs={}".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(session_cookie,"standalone"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.auth2_envs={}".format(auth2_envs))

            finally:
                self.shutdown_all_auth2_servers()
                pass
        
        
    def test_migrate_to_default_cluster(self):
        """
        Test the feature "upgrade the session to cluster session of the same cluster server'
        """
        print("************Begin to run test case 'test_migrate_to_default_cluster'******************************")
        index = 0
        for auth2_envs in [
            {},
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "auth01":{
                    "STANDALONE_CACHE_KEY_PREFIX":"standalone"
                }
            },
            {
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth01"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth01",
                    "STANDALONE_CACHE_KEY_PREFIX":"standalone"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth2",
                    "STANDALONE_CACHE_KEY_PREFIX":"auth2"
                }
            }
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(auth2_envs))

            try:
                #login to a standalone server to get a standalone session
                self.start_auth2_server("standalone",18060,auth2_env=auth2_envs.get("standalone"))
                res = requests.get(self.get_login_user_url("test_user01@test.com",servername="standalone"),headers=self.headers,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                cache_key_prefix = self.get_settings("CACHE_KEY_PREFIX","standalone")
                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                session_data,ttl = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
                print("\n")
    
                #migrate the standalone session to cluster server
                self.start_auth2_server("auth01",18061,auth2_env=auth2_envs.get("auth01"))
                auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                auth01_cache_key_prefix,auth01_standalone_cache_key_prefix = self.get_settings(["CACHE_KEY_PREFIX","STANDALONE_CACHE_KEY_PREFIX"],"auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                print("\n".join("{}={}".format(k,v) for k,v in res.json().items()))
                print("\n")
                auth01_session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                returned_auth01_lb_hash_key,auth01_clusterid,auth01_signature,auth01_session_key = auth01_session_cookie.split("|",3)
                self.assertEqual(auth01_lb_hash_key,returned_auth01_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-LB-HASH-KEY'.auth2_envs={}".format(auth2_envs))
                self.assertEqual(auth01_clusterid,"AUTH2_01",msg="Auth2 clusterid({}) should be 'AUTH2_01',auth2_envs={}".format(auth01_clusterid,auth2_envs))
                self.assertEqual(session_cookie,auth01_session_key,msg="Cluster session id should be populated from original session key.auth2_envs={}".format(auth2_envs))
                auth01_user_profile = res.json()
                self.assertEqual(auth01_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth01_session_data,ttl = self.get_session_data(auth01_session_cookie,"auth01")
                self.assertEqual(auth01_session_data,session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth01_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile.items()))
                print("\n")
    
                #session has migrated from standalone server to cluster server,
                #check the original session 
                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile3 = res.json()
                if cache_key_prefix == auth01_cache_key_prefix:
                    self.assertEqual(user_profile3["authenticated"],True,msg="The cluster session has the same cache key as the non-cluster session, the previous session cookie is still accessable.auth2_envs={}".format(auth2_envs))
                else:
                    self.assertEqual(user_profile3["authenticated"],False,msg="The cluster session has the different cache key from the non-cluster session, the previous session cookie is not available.auth2_envs={}".format(auth2_envs))
                    self.assertEqual(self.is_session_deleted(session_cookie,"standalone"),True,msg="The cluster session has the different cache key with the non-cluster session, the previous session cookie should be deleted during migration.auth2_envs={}".format(auth2_envs))
    
                #try to migrate the standalone session to cluster server again.
                #The same session cookie should be returned
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_session_cookie2 = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                self.assertEqual(auth01_session_cookie2,auth01_session_cookie,msg="The session cookie should be same no matter how many times a session is migrated to the same cluster server.auth2_envs={}".format(auth2_envs))
                auth01_user_profile2 = res.json()
                self.assertEqual(auth01_user_profile2["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth01_session_data2,ttl = self.get_session_data(auth01_session_cookie2,"auth01")
                self.assertEqual(auth01_session_data2,session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
    
            finally:
                self.shutdown_all_auth2_servers()
                pass
        
    def test_migrate_to_default_cluster_with_previous_cache(self):
        """
        Test the feature "upgrade the session to cluster session of the same cluster server with previous session cache enabled'
        standalone: non-cluster server
        standalone2: non-cluster server;the previous session cache server is the sesseion cache server of auth2 server 'standalone'
        auth02a: a default cluster server;the previous session cache server is the sesseion cache server of auth2 server 'standalone'. it has the same session cache server as auth2 server 'standalone2'

        """
        print("************Begin to run test case 'test_migrate_to_default_cluster_with_previous_cache'******************************")
        index = 0
        for auth2_envs in [
            {},
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "standalone2":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone"
                },
                "auth02a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone"
                }
            },
            {
                "standalone2":{
                    "CACHE_KEY_PREFIX":"standalone2"
                },
                "auth02a":{
                    "STANDALONE_CACHE_KEY_PREFIX":"standalone2",
                    "CACHE_KEY_PREFIX":"auth02"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "standalone2":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone",
                    "CACHE_KEY_PREFIX":"standalone2"
                },
                "auth02a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone",
                    "STANDALONE_CACHE_KEY_PREFIX":"standalone2",
                    "CACHE_KEY_PREFIX":"auth02"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"auth2",
                },
                "standalone2":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth2",
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth02a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth2",
                    "STANDALONE_CACHE_KEY_PREFIX":"auth2",
                    "CACHE_KEY_PREFIX":"auth2"
                }
            },
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(auth2_envs))
            try:
                #login to a server 'standalone' to get a standalone session cookie
                self.start_auth2_server("standalone",18060,auth2_env=auth2_envs.get("standalone"))
                self.start_auth2_server("standalone2",18061,auth2_env=auth2_envs.get("standalone2"))
                standalone_cache_key_prefix = self.get_settings("CACHE_KEY_PREFIX","standalone")
                standalone2_cache_key_prefix = self.get_settings("CACHE_KEY_PREFIX","standalone2")
                res = requests.get(self.get_login_user_url("test_user01@test.com",servername="standalone"),headers=self.headers,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                session_data,ttl = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
                print("\n")

                #migrate the session to cluster server 'auth02a'
                self.start_auth2_server("auth02a",18062,auth2_env=auth2_envs.get("auth02a"))
                auth02a_cache_key_prefix,auth02a_standalone_cache_key_prefix = self.get_settings(["CACHE_KEY_PREFIX","STANDALONE_CACHE_KEY_PREFIX"],"auth02a")
                auth02_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth02")
                self.cluster_headers["X-LB-HASH-KEY"] = auth02_lb_hash_key
                res = requests.get(self.get_profile_url(servername="auth02a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth02_session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                returned_auth02_lb_hash_key,auth02_clusterid,auth2_signature,auth02_session_key = auth02_session_cookie.split("|",3)
                self.assertEqual(auth02_lb_hash_key,returned_auth02_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-LB-HASH-KEY'.auth2_envs={}".format(auth2_envs))
                self.assertEqual(auth02_clusterid,"AUTH2_02",msg="Auth2 clusterid({}) should be 'AUTH2_02',auth2_envs={}".format(auth02_clusterid,auth2_envs))
                self.assertEqual(session_cookie,auth02_session_key,msg="Cluster session id should be populated from original session key.auth2_envs={}".format(auth2_envs))
                auth02_user_profile = res.json()
                self.assertEqual(auth02_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth02_session_data,ttl = self.get_session_data(auth02_session_cookie,"auth02a")
                self.assertEqual(auth02_session_data,session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth02_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth02_user_profile.items()))
                print("\n")

                #session has migrated from server 'standalone' to cluster server 'auth02a',
                #the session should be invalidated in auth2 server 'standalone'
                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile3 = res.json()
                self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.auth2_envs={}".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(session_cookie,"standalone"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.auth2_envs={}".format(auth2_envs))
    
                #the session should be invalidated in auth2 server 'standalone2' if cache key prefix is different; otherwise shoule be still available
                res = requests.get(self.get_profile_url(servername="standalone2"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile4 = res.json()
                if standalone2_cache_key_prefix == auth02a_cache_key_prefix:
                    self.assertEqual(user_profile4["authenticated"],True,msg="The cluster session has the same cache key as the non-cluster session, the previous session cookie is still accessable.auth2_envs={}".format(auth2_envs))
                else:
                    self.assertEqual(user_profile4["authenticated"],False,msg="The cluster session has the different cache key with the non-cluster session, the previous session cookie is not available.auth2_envs={}".format(auth2_envs))
                    self.assertEqual(self.is_session_deleted(session_cookie,"standalone2"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.auth2_envs={}".format(auth2_envs))

                #try to migrate the standalone session to cluster server again.
                res = requests.get(self.get_profile_url(servername="auth02a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth02_session_cookie2 = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                self.assertEqual(auth02_session_cookie2,auth02_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.auth2_envs={}".format(auth2_envs))
                auth02_user_profile2 = res.json()
                self.assertEqual(auth02_user_profile2["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth02_session_data2,ttl = self.get_session_data(auth02_session_cookie2,"auth02a")
                self.assertEqual(auth02_session_data2,session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth02_session_cookie2))
                print("\n")
    
            finally:
                self.shutdown_all_auth2_servers()
                pass
        
    def test_migrate_to_other_cluster(self):
        """
        Test the feature "upgrade the session to cluster session of the other cluster server'
        standalone: a non-cluster server
        auth01: a default cluster server; it has the same session cache server as server 'standalone'
        auth02: a cluster server
        """
        print("************Begin to run test case 'test_migrate_to_other_cluster'******************************")
        index = 0
        for auth2_envs in [
            {},
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "auth01":{
                    "STANDALONE_CACHE_KEY_PREFIX":"standalone"
                }
            },
            {
                "auth02":{
                    "CACHE_KEY_PREFIX":"auth02"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "auth02":{
                    "CACHE_KEY_PREFIX":"auth02"
                },
                "auth01":{
                    "STANDALONE_CACHE_KEY_PREFIX":"standalone"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth02":{
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth01":{
                    "STANDALONE_CACHE_KEY_PREFIX":"auth2"
                }
            }
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(auth2_envs))
            try:
                #login to a server 'standalone' to get a standalone session cookie
                self.start_auth2_server("standalone",18060,auth2_env=auth2_envs.get("standalone"))
                standalone_cache_key_prefix = self.get_settings("CACHE_KEY_PREFIX","standalone")
                res = requests.get(self.get_login_user_url("test_user01@test.com",servername="standalone"),headers=self.headers,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                print("session cookie = {}".format(session_cookie))

                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs=".format(auth2_envs))
                session_data,ttl = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
    
                #migrate to session to auth02
                self.start_auth2_server("auth01",18061,auth2_env=auth2_envs.get("auth01"))
                self.start_auth2_server("auth02",18062,auth2_env=auth2_envs.get("auth02"))
                auth01_cache_key_prefix,auth01_standalone_cache_key_prefix = self.get_settings(["CACHE_KEY_PREFIX","STANDALONE_CACHE_KEY_PREFIX"],"auth01")
                auth02_cache_key_prefix,auth02_standalone_cache_key_prefix = self.get_settings(["CACHE_KEY_PREFIX","STANDALONE_CACHE_KEY_PREFIX"],"auth02")
                auth02_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth02_lb_hash_key
                res = requests.get(self.get_profile_url(servername="auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth02_session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])

                returned_auth02_lb_hash_key,auth02_clusterid,auth02_signature,auth02_session_key = auth02_session_cookie.split("|",3)
                self.assertEqual(auth02_lb_hash_key,returned_auth02_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-LB-HASH-KEY'.auth2_env=".format(auth2_envs))
                self.assertEqual(auth02_clusterid,"AUTH2_02",msg="Auth2 clusterid({}) should be 'AUTH2_01'.auth2_envs=".format(auth02_clusterid,auth2_envs))
                self.assertEqual(session_cookie,auth02_session_key,msg="Cluster session id should be populated from original session key.auth2_envs=".format(auth2_envs))
                auth02_user_profile = res.json()
                self.assertEqual(auth02_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs=".format(auth2_envs))
                auth02_session_data,ttl = self.get_session_data(auth02_session_cookie,"auth02")
                self.assertEqual(auth02_session_data,session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth02_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth02_user_profile.items()))
    
                #session has migrated from server 'standalone' to cluster server 'auth02',
                #check whether the session is not available in server 'standalone' and 'auth01'
                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile3 = res.json()
                self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.auth2_envs=".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(session_cookie,"standalone"),True,msg="The migrated session should be deleted from original server 'standalone'.auth2_envs={}".format(auth2_envs))

                self.assertEqual(self.is_session_deleted(session_cookie,"auth01"),True,msg="The migrated session data should be delete from default cluster server 'auth01' .auth2_envs={}".format(auth2_envs))
    
                #try to migrate the standalone session to cluster server again.
                res = requests.get(self.get_profile_url(servername="auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth02_session_cookie2 = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                self.assertEqual(auth02_session_cookie2,auth02_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.auth2_envs=".format(auth2_envs))
                auth02_user_profile2 = res.json()
                self.assertEqual(auth02_user_profile2["authenticated"],True,msg="User should have already loged in.auth2_envs=".format(auth2_envs))
                auth02_session_data2,ttl = self.get_session_data(auth02_session_cookie2,"auth02")
                self.assertEqual(auth02_session_data2,session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth02_session_cookie2))
    
            finally:
                self.shutdown_all_auth2_servers()
                pass

    def test_migrate_to_other_cluster_with_previous_cache(self):
        """
        Test the feature "upgrade the session to cluster session of the other cluster server with previous session cache enabled'
        standalone: non-cluster server
        standalon2: non-cluster server, the previous session cache server is the session cache server of auth2 server 'standalone'
        auth02a: default cluster server, has the same session cache server as the auth2 server 'standalone2', the previous session cache server is the session cache server of auth2 server 'standalone'
        auth03: a cluster server
        """
        print("************Begin to run test case 'test_migrate_to_other_cluster_with_previous_cache'******************************")
        index = 0
        for auth2_envs in [
            {},
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "standalone2":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone"
                },
                "auth02a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone"
                }
            },
            {
                "standalone2":{
                    "CACHE_KEY_PREFIX":"standalone2"
                },
                "auth02a":{
                    "STANDALONE_CACHE_KEY_PREFIX":"standalone2",
                    "CACHE_KEY_PREFIX":"auth02"
                },
                "auth03":{
                    "CACHE_KEY_PREFIX":"auth03"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"standalone"
                },
                "standalone2":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone",
                    "CACHE_KEY_PREFIX":"standalone2"
                },
                "auth02a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"standalone",
                    "STANDALONE_CACHE_KEY_PREFIX":"standalone2",
                    "CACHE_KEY_PREFIX":"auth02"
                },
                "auth03":{
                    "CACHE_KEY_PREFIX":"auth03"
                }
            },
            {
                "standalone":{
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "standalone2":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth2",
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth02a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth2",
                    "STANDALONE_CACHE_KEY_PREFIX":"auth2",
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth03":{
                    "CACHE_KEY_PREFIX":"auth2"
                }
            }
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(auth2_envs))

            try:
                #login to a server 'standalone' to get the standalone session cookie
                self.start_auth2_server("standalone",18060,auth2_env=auth2_envs.get("standalone"))
                self.start_auth2_server("standalone2",18061,auth2_env=auth2_envs.get("standalone2"))
                standalone_cache_key_prefix = self.get_settings("CACHE_KEY_PREFIX","standalone")
                standalone2_cache_key_prefix = self.get_settings("CACHE_KEY_PREFIX","standalone2")
                res = requests.get(self.get_login_user_url("test_user01@test.com",servername="standalone"),headers=self.headers,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                session_data,ttl = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
                print("\n")
    
                #migrate the session to cluster server 'auth03'
                self.start_auth2_server("auth02a",18062,auth2_env=auth2_envs.get("auth02a"))
                self.start_auth2_server("auth03",18063,auth2_env=auth2_envs.get("auth03"))
                auth02a_cache_key_prefix,auth02a_standalone_cache_key_prefix = self.get_settings(["CACHE_KEY_PREFIX","STANDALONE_CACHE_KEY_PREFIX"],"auth02a")
                auth03_cache_key_prefix,auth03_standalone_cache_key_prefix = self.get_settings(["CACHE_KEY_PREFIX","STANDALONE_CACHE_KEY_PREFIX"],"auth03")
                auth03_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth03")
                self.cluster_headers["X-LB-HASH-KEY"] = auth03_lb_hash_key
                res = requests.get(self.get_profile_url(servername="auth03"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth03_session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                returned_auth03_lb_hash_key,auth03_clusterid,signature,auth03_session_key = auth03_session_cookie.split("|",3)
                self.assertEqual(auth03_lb_hash_key,returned_auth03_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-LB-HASH-KEY'.auth2_envs={}".format(auth2_envs))
                self.assertEqual(auth03_clusterid,"AUTH2_03",msg="Auth2 clusterid({}) should be 'AUTH2_01',auth2_envs={}".format(auth03_clusterid,auth2_envs))
                self.assertEqual(session_cookie,auth03_session_key,msg="Cluster session id should be populated from original session key.auth2_envs={}".format(auth2_envs))
                auth03_user_profile = res.json()
                self.assertEqual(auth03_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth03_session_data,ttl = self.get_session_data(auth03_session_cookie,"auth03")
                self.assertEqual(auth03_session_data,session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth03_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth03_user_profile.items()))
                print("\n")

                #session has migrated from server 'standalone' to cluster server 'auth03',
                #check whether the session is not available in auth2 server 'standalone'
                res = requests.get(self.get_profile_url(servername="standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile3 = res.json()
                self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.auth2_envs={}".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(session_cookie,"standalone"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.auth2_envs={}".format(auth2_envs))
    
                #check whether the session is not available in auth2 server 'standalone2'
                res = requests.get(self.get_profile_url(servername="standalone2"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile4 = res.json()
                self.assertEqual(user_profile4["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.auth2_envs={}".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(session_cookie,"standalone2"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.auth2_envs={}".format(auth2_envs))

                #check whether the session is not available in auth2 server 'auth02a'
                res = requests.get(self.get_profile_url(servername="auth02a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                user_profile5 = res.json()
                self.assertEqual(user_profile5["authenticated"],False,msg="The original session has been deleted, can't use it to access anymore.auth2_envs={}".format(auth2_envs))

                auth02_session_cookie = self.get_cluster_session_cookie("AUTH2_02",auth03_session_cookie)
                self.assertEqual(self.is_session_deleted(session_cookie,"auth02a"),True,msg="The migrated session data should be deleted.auth2_envs={}".format(auth2_envs))

                #try to migrate the standalone session to cluster server again.
                res = requests.get(self.get_profile_url(servername="auth03"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth03_session_cookie2 = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                self.assertEqual(auth03_session_cookie2,auth03_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.auth2_envs={}".format(auth2_envs))
                auth03_user_profile2 = res.json()
                self.assertEqual(auth03_user_profile2["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth03_session_data2,ttl = self.get_session_data(auth03_session_cookie2,"auth03")
                self.assertEqual(auth03_session_data2,session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth03_session_cookie2))
                print("\n")
    
            finally:
                self.shutdown_all_auth2_servers()
                pass
        
    def test_migrate_session_among_clusters(self):
        """
        Test the feature "migrate the session among clusters'
        auth01: a default cluster server
        auth02: another cluster server
        """
        print("************Begin to run test case 'test_migrate_session_among_clusters'******************************")
        index = 0
        for auth2_envs in [
            {},
            {
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth01"
                }
            },
            {
                "auth02":{
                    "CACHE_KEY_PREFIX":"auth02"
                }
            },
            {
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth01"
                },
                "auth02":{
                    "CACHE_KEY_PREFIX":"auth02"
                }
            },
            {
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth02":{
                    "CACHE_KEY_PREFIX":"auth2"
                }
            },
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(auth2_envs))
            try:
                self.start_auth2_server("auth01",18060,auth2_env=auth2_envs.get("auth01"))
                self.start_auth2_server("auth02",18061,auth2_env=auth2_envs.get("auth02"))
    
                #login to auth2 server 'auth01' to get a cluster session cookie
                auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_login_user_url("test_user01@test.com",servername="auth01"),headers=self.cluster_headers,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_session_cookie = self.unquotedcookie(self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME]))
                returned_auth01_lb_hash_key,auth01_clusterid,auth01_signature,auth01_session_key = auth01_session_cookie.split("|",3)
                self.assertEqual(returned_auth01_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as passed in lb hash key.auth2_envs=".format(auth2_envs))
                self.assertEqual(auth01_clusterid,"AUTH2_01",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth01'.auth2_envs=".format(auth2_envs))
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_user_profile = res.json()
                self.assertEqual(auth01_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs=".format(auth2_envs))
                auth01_session_data,ttl = self.get_session_data(auth01_session_cookie,"auth01")
                print("original session cookie = {}".format(auth01_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile.items()))
    
                #migrate the session to auth2 server 'auth02'
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_profile_url(servername="auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth02_session_cookie = self.unquotedcookie(self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME]))
                returned_auth02_lb_hash_key,auth02_clusterid,auth2_signature,auth02_session_key = auth02_session_cookie.split("|",3)
                self.assertEqual(returned_auth02_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as lb session key in original sesion cookie.auth2_envs=".format(auth2_envs))
                self.assertEqual(auth02_clusterid,"AUTH2_02",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth02'.auth2_envs=".format(auth2_envs))
                self.assertEqual(auth02_session_key,auth01_session_key,msg="The session key should not be changed during migration.auth2_envs=".format(auth2_envs))
                auth02_user_profile = res.json()
                self.assertEqual(auth02_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs=".format(auth2_envs))
                auth02_session_data,ttl = self.get_session_data(auth02_session_cookie,"auth02")
                self.assertEqual(auth02_session_data,auth01_session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("migrated the auth01 sesesion cookie '{}' to auth02 session cookie  '{}'".format(auth01_session_cookie,auth02_session_cookie))
                print("\n")
    
                #session has migrated from auth01 to auth02
                #check whether the original session is not available in original auth2 serve 'auth01'
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_user_profile2 = res.json()
                self.assertEqual(auth01_user_profile2["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.auth2_envs=".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(auth01_session_cookie,"auth01"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.auth2_envs={}".format(auth2_envs))
    
                #try to migrate the session from auth01 to auth02 again.
                res = requests.get(self.get_profile_url(servername="auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth02_session_cookie2 = self.unquotedcookie(self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME]))
                self.assertEqual(auth02_session_cookie2,auth02_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.auth2_envs=".format(auth2_envs))
                auth02_user_profile2 = res.json()
                self.assertEqual(auth02_user_profile2["authenticated"],True,msg="User should have already loged in.auth2_envs=".format(auth2_envs))
                auth02_session_data2,ttl = self.get_session_data(auth02_session_cookie2,"auth02")
                self.assertEqual(auth02_session_data2,auth01_session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("\n")
    
                #migrate back to auth01
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth02_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_user_profile3 = res.json()
                auth01_session_cookie3 = self.unquotedcookie(self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME]))
                self.assertEqual(auth01_session_cookie3,auth01_session_cookie,msg="The session cookie of the migrated back session should be the same value as the original session cookie.auth2_envs=".format(auth2_envs))
                self.assertEqual(auth01_user_profile3["authenticated"],True,msg="User should have already loged in.auth2_envs=".format(auth2_envs))
                auth01_session_data3,ttl = self.get_session_data(auth01_session_cookie3,"auth01")
                self.assertEqual(auth01_session_data3,auth01_session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("migrated the auth2 session cookie '{}' back to auth01 session cookie = {}".format(auth02_session_cookie,auth01_session_cookie3))
                print("\n")
    
                #session has migrated from auth02 to auth01
                #it should be failed if try to use the original session to access auth02
                res = requests.get(self.get_profile_url(servername="auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth02_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth02_user_profile3 = res.json()
                self.assertEqual(auth02_user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.auth2_envs=".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(auth02_session_cookie,"auth02"),True,msg="The migrated session data should be deleted.auth2_envs={}".format(auth2_envs))
    
                #try to migrate the session from auth02 to auth01 again.
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth02_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_user_profile4 = res.json()
                auth01_session_cookie4 = self.unquotedcookie(self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME]))
                self.assertEqual(auth01_session_cookie4,auth01_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.auth2_envs=".format(auth2_envs))
                self.assertEqual(auth01_user_profile4["authenticated"],True,msg="User should have already loged in.auth2_envs=".format(auth2_envs))
                auth01_session_data4,ttl = self.get_session_data(auth01_session_cookie4,"auth01")
                self.assertEqual(auth01_session_data4,auth01_session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("\n")
    
            finally:
                self.shutdown_all_auth2_servers()
    
        
    def test_cluster_with_previous_cache(self):
        """
        Test the feature 'cluster with previous session cache enabled'
        auth01: a default cluster server
        auth01a: a cluster server with same cluster id as 'auth01', its previous session cache server is session cache server of 'auth01'
        """
        print("************Begin to run test case 'test_cluster_with_previous_cache'******************************")
        index = 0
        for auth2_envs in [
            {},
            {
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth01"
                },
                "auth01a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth01"
                },
            },
            {
                "auth01a":{
                    "CACHE_KEY_PREFIX":"auth01a"
                }
            },
            {
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth01"
                },
                "auth01a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth01",
                    "CACHE_KEY_PREFIX":"auth01a"
                }
            },
            {
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth01a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth2",
                    "CACHE_KEY_PREFIX":"auth2"
                }
            }
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(auth2_envs))

            try:
                #login to auth2 server 'auth01' to get a cluster session cookie
                self.start_auth2_server("auth01",18060,auth2_env=auth2_envs.get("auth01"))
                auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_login_user_url("test_user01@test.com",servername="auth01"),headers=self.cluster_headers,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_session_cookie = self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME])
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_user_profile = res.json()
                self.assertEqual(auth01_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth01_session_data,ttl = self.get_session_data(auth01_session_cookie,"auth01")
                print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile.items()))
                print("\n")

                #auth01a's previous session cache is the session cache of cluster 'auth01'
                #Use session cookie to access auth01a to migrate the session from previous session cache to auth01a's session cache
                self.shutdown_auth2_server("auth01")
                self.start_auth2_server("auth01a",18060,auth2_env=auth2_envs.get("auth01a"))
                #use the session cookie to access auth01a to migrate the session from previous session cache to auth01a's session cache
                res = requests.get(self.get_profile_url(servername="auth01a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                self.assertEqual(self.unquotedcookie(res.cookies.get(settings.SESSION_COOKIE_NAME)),None,msg="Session is only migrated from previous session cache. and the client session cookie should not be changed..auth2_envs={}".format(auth2_envs))
                auth01a_user_profile = res.json()
                self.assertEqual(auth01a_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth01a_session_data,ttl = self.get_session_data(auth01_session_cookie,"auth01a")
                self.assertEqual(auth01a_session_data,auth01_session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))
                print("\n".join("{}={}".format(k,v) for k,v in auth01a_user_profile.items()))
                print("\n")

                #session has migrated from previous cache, check whether the session in previous session cache is not available
                self.shutdown_auth2_server("auth01a")
                self.start_auth2_server("auth01",18060,auth2_env=auth2_envs.get("auth01"))
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_user_profile2 = res.json()
                self.assertEqual(auth01_user_profile2["authenticated"],False,msg="The session has been migrated from original session cache..auth2_envs={}".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(auth01_session_cookie,"auth01"),True,msg="The migrated session data should be deleted.auth2_envs={}".format(auth2_envs))

            finally:
                self.shutdown_all_auth2_servers()
                pass
        
    def test_migrate_among_clusters_with_previous_cache(self):
        """
        Test the feature "migrate the session among clusters with previous session cache enabled'
        auth01: the default cluster server
        auth01a: the cluster server with the same clusterid as 'auth01', its previous session cache server is the session cache server of 'auth01'
        auth03: another cluster server
        """
        print("************Begin to run test case 'test_migrate_among_clusters_with_previous_cache'******************************")
        index = 0
        for auth2_envs in [
            {},
            {
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth01"
                },
                "auth01a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth01"
                },
            },{
                "auth01a":{
                    "CACHE_KEY_PREFIX":"auth01a"
                },
                "auth03":{
                    "CACHE_KEY_PREFIX":"auth03"
                }
            },{
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth01"
                },
                "auth01a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth01",
                    "CACHE_KEY_PREFIX":"auth01a"
                },
                "auth03":{
                    "CACHE_KEY_PREFIX":"auth03"
                }
            },{
                "auth01":{
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth01a":{
                    "PREVIOUS_CACHE_KEY_PREFIX":"auth2",
                    "CACHE_KEY_PREFIX":"auth2"
                },
                "auth03":{
                    "CACHE_KEY_PREFIX":"auth2"
                }
            }
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(auth2_envs))

            try:
                #login to auth2 server 'auth01' to get a cluster session cookie
                self.start_auth2_server("auth01",18060,auth2_env=auth2_envs.get("auth01"))
                auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_login_user_url("test_user01@test.com",servername="auth01"),headers=self.cluster_headers,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_session_cookie = self.unquotedcookie(self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME]))
                returned_auth01_lb_hash_key,auth01_clusterid,auth01_signature,auth01_session_key = auth01_session_cookie.split("|",3)
                self.assertEqual(returned_auth01_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as lb session key in original sesion cookie.auth2_envs=".format(auth2_envs))
                self.assertEqual(auth01_clusterid,"AUTH2_01",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth02'.auth2_envs=".format(auth2_envs))
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_user_profile = res.json()
                self.assertEqual(auth01_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth01_session_data,ttl = self.get_session_data(auth01_session_cookie,"auth01")
                print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile.items()))
                print("\n")

                #migrqte the session from auth01a to auth03
                self.shutdown_auth2_server("auth01")
                self.start_auth2_server("auth01a",18060,auth2_env=auth2_envs.get("auth01a"))
                self.start_auth2_server("auth03",18061,auth2_env=auth2_envs.get("auth03"))
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_profile_url(servername="auth03"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth03_user_profile = res.json()
                auth03_session_cookie = self.unquotedcookie(self.unquotedcookie(res.cookies[settings.SESSION_COOKIE_NAME]))
                returned_auth03_lb_hash_key,auth03_clusterid,auth03_signature,auth03_session_key = auth03_session_cookie.split("|",3)
                self.assertEqual(returned_auth03_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as lb session key in original sesion cookie.auth2_envs=".format(auth2_envs))
                self.assertEqual(auth03_clusterid,"AUTH2_03",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth02'.auth2_envs=".format(auth2_envs))
                self.assertEqual(auth03_session_key,auth01_session_key,msg="The random generated session key(not including the hash value of lb hash key and auth2 cluster id) should be the same value as the migrated session key.auth2_envs=".format(auth2_envs))
                self.assertEqual(auth03_user_profile["authenticated"],True,msg="User should have already loged in.auth2_envs={}".format(auth2_envs))
                auth03_session_data,ttl = self.get_session_data(auth03_session_cookie,"auth03")
                self.assertEqual(auth03_session_data,auth01_session_data,msg="Session data should not be changed during migration.auth2_envs={}".format(auth2_envs))

                #session has migrated from previous cache, check whether it is not available in the original session cache
                res = requests.get(self.get_profile_url(servername="auth01a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01a_user_profile2 = res.json()
                self.assertEqual(auth01a_user_profile2["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.auth2_envs={}".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(auth01_session_cookie,"auth01a"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.auth2_envs={}".format(auth2_envs))

                self.shutdown_auth2_server("auth01a")
                self.start_auth2_server("auth01",18060,auth2_env=auth2_envs.get("auth01"))
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie},verify=settings.SSL_VERIFY)
                res.raise_for_status()
                auth01_user_profile3 = res.json()
                self.assertEqual(auth01_user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.auth2_envs={}".format(auth2_envs))
                self.assertEqual(self.is_session_deleted(auth01_session_cookie,"auth01"),True,msg="The migrated session data should be deleted.auth2_envs={}".format(auth2_envs))

            finally:
                self.shutdown_all_auth2_servers()
                pass
        
