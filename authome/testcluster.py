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
    def test_previous_session_cache(self):
        """
        Test the feature 'Migrate the session from previous session cache' for standalone auth2 server
        """
        print("************Begin to run test case 'test_previous_session_cache'******************************")
        index = 0
        for commands in [
            {},
            {"standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX","standalone2":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX"},
            {"standalone2":"CACHE_KEY_PREFIX=standalone2&&export CACHE_KEY_PREFIX"},
            {"standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX","standalone2":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=standalone2&&export CACHE_KEY_PREFIX"},
            {"standalone":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX","standalone2":"PREVIOUS_CACHE_KEY_PREFIX=auth2&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX"},
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(commands))

            try:
                #login to a standalone server to get the standalone session cookie 
                self.start_auth2_server("standalone",18060,precommands=commands.get("standalone"))
                res = requests.get(self.get_login_user_url("test_user01@test.com","standalone"),headers=self.headers)
                res.raise_for_status()
                session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                session_data = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
                print("\n")
    
                #start server 'standalone2' whose previous session cache is the session cache of server 'standalone'
                #use the session cookie to access server 'standalone2' to migrate the session to session cache of server 'standalone'
                self.start_auth2_server("standalone2",18061,precommands=commands.get("standalone2"))
                res = requests.get(self.get_profile_url("standalone2"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                self.assertEqual(res.cookies.get(settings.SESSION_COOKIE_NAME),None,msg="Session is only migrated from previous session cache. and the client session cookie should not be changed..commands={}".format(commands))
                user_profile2 = res.json()
                self.assertEqual(user_profile2["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                session_data2 = self.get_session_data(session_cookie,"standalone2")
                self.assertEqual(session_data2,session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("\n".join("{}={}".format(k,v) for k,v in user_profile2.items()))
                print("\n")
    
                #session has migrated from previous cache,check whether the session in the original session cache is invalidated.
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile3 = res.json()
                self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands={}".format(commands))
                self.assertEqual(self.is_session_migrated(session_cookie,"standalone"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))

            finally:
                self.shutdown_all_auth2_servers()
                pass
        
        
    def test_migrate_to_default_cluster(self):
        """
        Test the feature "upgrade the session to cluster session of the same cluster server'
        """
        print("************Begin to run test case 'test_migrate_to_default_cluster'******************************")
        index = 0
        for commands in [
            {},
            {"standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX","auth01":"STANDALONE_CACHE_KEY_PREFIX=standalone&&export STANDALONE_CACHE_KEY_PREFIX"},
            {"auth01":"CACHE_KEY_PREFIX=auth01&&export CACHE_KEY_PREFIX"},
            {"standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX","auth01":"CACHE_KEY_PREFIX=auth01;STANDALONE_CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIXl;export STANDALONE_CACHE_KEY_PREFIX"},
            {"standalone":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX","auth01":"CACHE_KEY_PREFIX=auth2;STANDALONE_CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIXl;export STANDALONE_CACHE_KEY_PREFIX"}
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(commands))

            try:
                #login to a standalone server to get a standalone session
                self.start_auth2_server("standalone",18060,precommands=commands.get("standalone"))
                res = requests.get(self.get_login_user_url("test_user01@test.com","standalone"),headers=self.headers)
                res.raise_for_status()
                session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                session_data = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
                print("\n")
    
                #migrate the standalone session to cluster server
                self.start_auth2_server("auth01",18061,precommands=commands.get("auth01"))
                auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                auth01_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                returned_auth01_lb_hash_key,auth01_clusterid,auth01_session_key = auth01_session_cookie.split("|",2)
                self.assertEqual(auth01_lb_hash_key,returned_auth01_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-LB-HASH-KEY'.commands={}".format(commands))
                self.assertEqual(auth01_clusterid,"AUTH2_01",msg="Auth2 clusterid({}) should be 'AUTH2_01',commands={}".format(auth01_clusterid,commands))
                self.assertEqual(session_cookie,auth01_session_key[:-2-16] + auth01_session_key[-2:],msg="Cluster session id should be populated from original session key.commands={}".format(commands))
                auth01_user_profile = res.json()
                self.assertEqual(auth01_user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth01_session_data = self.get_session_data(auth01_session_cookie,"auth01")
                self.assertEqual(auth01_session_data,session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth01_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile.items()))
                print("\n")
    
                #session has migrated from standalone server to cluster server,
                #check whether the original session is invalidated.
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile3 = res.json()
                self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands={}".format(commands))
                self.assertEqual(self.is_session_migrated(session_cookie,"standalone"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))
    
                #try to migrate the standalone session to cluster server again.
                #The same session cookie should be returned
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                auth01_session_cookie2 = res.cookies[settings.SESSION_COOKIE_NAME]
                self.assertEqual(auth01_session_cookie2,auth01_session_cookie,msg="The session cookie should be same no matter how many times a session is migrated to the same cluster server.commands={}".format(commands))
                auth01_user_profile2 = res.json()
                self.assertEqual(auth01_user_profile2["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth01_session_data2 = self.get_session_data(auth01_session_cookie2,"auth01")
                self.assertEqual(auth01_session_data2,session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
    
            finally:
                self.shutdown_all_auth2_servers()
                pass
        
    def test_migrate_to_default_cluster_with_previous_cache(self):
        """
        Test the feature "upgrade the session to cluster session of the same cluster server with previous session cache enabled'
        """
        print("************Begin to run test case 'test_migrate_to_default_cluster_with_previous_cache'******************************")
        index = 0
        for commands in [
            {},
            {"standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX","standalone2":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX","auth02a":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX"},
            {"standalone2":"CACHE_KEY_PREFIX=standalone2&&export CACHE_KEY_PREFIX","auth02a":"STANDALONE_CACHE_KEY_PREFIX=standalone2&&export STANDALONE_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth02&&export CACHE_KEY_PREFIX"},
            {"standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX","standalone2":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=standalone2&&export CACHE_KEY_PREFIX","auth02a":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX&&STANDALONE_CACHE_KEY_PREFIX=standalone2&&export STANDALONE_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth02&&export CACHE_KEY_PREFIX"},
            {"standalone":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX","standalone2":"PREVIOUS_CACHE_KEY_PREFIX=auth2&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX","auth02a":"PREVIOUS_CACHE_KEY_PREFIX=auth2&&export PREVIOUS_CACHE_KEY_PREFIX&&STANDALONE_CACHE_KEY_PREFIX=auth2&&export STANDALONE_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX"},
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(commands))
            try:
                #login to a standalone server to get a standalone session cookie
                self.start_auth2_server("standalone",18060,precommands=commands.get("standalone"))
                self.start_auth2_server("standalone2",18061,precommands=commands.get("standalone2"))
                res = requests.get(self.get_login_user_url("test_user01@test.com","standalone"),headers=self.headers)
                res.raise_for_status()
                session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                session_data = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
                print("\n")
    
                #migrate the standalone to cluster server 'auth02a'
                self.start_auth2_server("auth02a",18062,precommands=commands.get("auth02a"))
                auth02_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth02")
                self.cluster_headers["X-LB-HASH-KEY"] = auth02_lb_hash_key
                res = requests.get(self.get_profile_url("auth02a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                auth02_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                returned_auth02_lb_hash_key,auth02_clusterid,auth02_session_key = auth02_session_cookie.split("|",2)
                self.assertEqual(auth02_lb_hash_key,returned_auth02_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-LB-HASH-KEY'.commands={}".format(commands))
                self.assertEqual(auth02_clusterid,"AUTH2_02",msg="Auth2 clusterid({}) should be 'AUTH2_02',commands={}".format(auth02_clusterid,commands))
                self.assertEqual(session_cookie,auth02_session_key[:-2-16] + auth02_session_key[-2:],msg="Cluster session id should be populated from original session key.commands={}".format(commands))
                auth02_user_profile = res.json()
                self.assertEqual(auth02_user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth02_session_data = self.get_session_data(auth02_session_cookie,"auth02a")
                self.assertEqual(auth02_session_data,session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth02_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth02_user_profile.items()))
                print("\n")

                #session has migrated from standalone server to cluster server,
                #the session should be invalidated in auth2 server 'standalone' and 'standalone2'
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile3 = res.json()
                self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands={}".format(commands))
                self.assertEqual(self.is_session_migrated(session_cookie,"standalone"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))
    
                res = requests.get(self.get_profile_url("standalone2"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile4 = res.json()
                self.assertEqual(user_profile4["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands={}".format(commands))
                self.assertEqual(self.is_session_migrated(session_cookie,"standalone2"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))

                #try to migrate the standalone session to cluster server again.
                res = requests.get(self.get_profile_url("auth02a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                auth02_session_cookie2 = res.cookies[settings.SESSION_COOKIE_NAME]
                self.assertEqual(auth02_session_cookie2,auth02_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.commands={}".format(commands))
                auth02_user_profile2 = res.json()
                self.assertEqual(auth02_user_profile2["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth02_session_data2 = self.get_session_data(auth02_session_cookie2,"auth02a")
                self.assertEqual(auth02_session_data2,session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth02_session_cookie2))
                print("\n")
    
            finally:
                self.shutdown_all_auth2_servers()
                pass
        
    def test_migrate_to_other_cluster(self):
        """
        Test the feature "upgrade the session to cluster session of the other cluster server'
        """
        print("************Begin to run test case 'test_migrate_to_other_cluster'******************************")
        index = 0
        for commands in [
            {},
            {"standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX","auth01":"STANDALONE_CACHE_KEY_PREFIX=standalone&&export STANDALONE_CACHE_KEY_PREFIX"},
            {"auth02":"CACHE_KEY_PREFIX=auth02&&export CACHE_KEY_PREFIX"},
            {"standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX","auth02":"CACHE_KEY_PREFIX=auth02&&export CACHE_KEY_PREFIX","auth01":"STANDALONE_CACHE_KEY_PREFIX=standalone&&export STANDALONE_CACHE_KEY_PREFIX"},
            {"standalone":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX","auth02":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX","auth01":"STANDALONE_CACHE_KEY_PREFIX=auth2&&export STANDALONE_CACHE_KEY_PREFIX"}
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(commands))
            try:
                #login to a standalone server to get a standalone session cookie
                self.start_auth2_server("standalone",18060,precommands=commands.get("standalone"))
                res = requests.get(self.get_login_user_url("test_user01@test.com","standalone"),headers=self.headers)
                res.raise_for_status()
                session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.commands=".format(commands))
                session_data = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
    
                #migrate to cluster server to auth02
                self.start_auth2_server("auth01",18061,precommands=commands.get("auth01"))
                self.start_auth2_server("auth02",18062,precommands=commands.get("auth02"))
                auth02_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth02_lb_hash_key
                res = requests.get(self.get_profile_url("auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                auth02_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                returned_auth02_lb_hash_key,auth02_clusterid,auth02_session_key = auth02_session_cookie.split("|",2)
                self.assertEqual(auth02_lb_hash_key,returned_auth02_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-LB-HASH-KEY'.commands=".format(commands))
                self.assertEqual(auth02_clusterid,"AUTH2_02",msg="Auth2 clusterid({}) should be 'AUTH2_01'.commands=".format(auth02_clusterid,commands))
                self.assertEqual(session_cookie,auth02_session_key[:-2-16] + auth02_session_key[-2:],msg="Cluster session id should be populated from original session key.commands=".format(commands))
                auth02_user_profile = res.json()
                self.assertEqual(auth02_user_profile["authenticated"],True,msg="User should have already loged in.commands=".format(commands))
                auth02_session_data = self.get_session_data(auth02_session_cookie,"auth02")
                self.assertEqual(auth02_session_data,session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth02_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth02_user_profile.items()))
    
                #session has migrated from standalone server to cluster server 'auth02',
                #it should be failed if try to use the original session to access standalone server
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile3 = res.json()
                self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands=".format(commands))
                self.assertEqual(self.is_session_migrated(session_cookie,"standalone"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))

                self.assertEqual(self.is_session_migrated(session_cookie,"auth01"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))
    
                #try to migrate the standalone session to cluster server again.
                res = requests.get(self.get_profile_url("auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                auth02_session_cookie2 = res.cookies[settings.SESSION_COOKIE_NAME]
                self.assertEqual(auth02_session_cookie2,auth02_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.commands=".format(commands))
                auth02_user_profile2 = res.json()
                self.assertEqual(auth02_user_profile2["authenticated"],True,msg="User should have already loged in.commands=".format(commands))
                auth02_session_data2 = self.get_session_data(auth02_session_cookie2,"auth02")
                self.assertEqual(auth02_session_data2,session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth02_session_cookie2))
    
            finally:
                self.shutdown_all_auth2_servers()
                pass

    def test_migrate_to_other_cluster_with_previous_cache(self):
        """
        Test the feature "upgrade the session to cluster session of the other cluster server with previous session cache enabled'
        """
        print("************Begin to run test case 'test_migrate_to_other_cluster_with_previous_cache'******************************")
        index = 0
        for commands in [
            {},
            {
                "standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX",
                "standalone2":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX",
                "auth02a":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX"
            },{
                "standalone2":"CACHE_KEY_PREFIX=standalone2&&export CACHE_KEY_PREFIX",
                "auth02a":"STANDALONE_CACHE_KEY_PREFIX=standalone2&&export STANDALONE_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth02&&export CACHE_KEY_PREFIX",
                "auth03":"CACHE_KEY_PREFIX=auth03&&export CACHE_KEY_PREFIX"
            },{
                "standalone":"CACHE_KEY_PREFIX=standalone&&export CACHE_KEY_PREFIX",
                "standalone2":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=standalone2&&export CACHE_KEY_PREFIX",
                "auth02a":"PREVIOUS_CACHE_KEY_PREFIX=standalone&&export PREVIOUS_CACHE_KEY_PREFIX&&STANDALONE_CACHE_KEY_PREFIX=standalone2&&export STANDALONE_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth02&&export CACHE_KEY_PREFIX",
                "auth03":"CACHE_KEY_PREFIX=auth03&&export CACHE_KEY_PREFIX"
            },{
                "standalone":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX",
                "standalone2":"PREVIOUS_CACHE_KEY_PREFIX=auth2&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX",
                "auth02a":"PREVIOUS_CACHE_KEY_PREFIX=auth2&&export PREVIOUS_CACHE_KEY_PREFIX&&STANDALONE_CACHE_KEY_PREFIX=auth2&&export STANDALONE_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX",
                "auth03":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX"
            }
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(commands))

            try:
                #login to a standalone server to get the standalone session cookie
                self.start_auth2_server("standalone",18060,precommands=commands.get("standalone"))
                self.start_auth2_server("standalone2",18061,precommands=commands.get("standalone2"))
                res = requests.get(self.get_login_user_url("test_user01@test.com","standalone"),headers=self.headers)
                res.raise_for_status()
                session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile = res.json()
                self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                session_data = self.get_session_data(session_cookie,"standalone")
                print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
                print("\n")
    
                #migrate the session to cluster server 'auth03'
                self.start_auth2_server("auth02a",18062,precommands=commands.get("auth02a"))
                self.start_auth2_server("auth03",18063,precommands=commands.get("auth03"))
                auth03_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth03")
                self.cluster_headers["X-LB-HASH-KEY"] = auth03_lb_hash_key
                res = requests.get(self.get_profile_url("auth03"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                auth03_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                returned_auth03_lb_hash_key,auth03_clusterid,auth03_session_key = auth03_session_cookie.split("|",2)
                self.assertEqual(auth03_lb_hash_key,returned_auth03_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-LB-HASH-KEY'.commands={}".format(commands))
                self.assertEqual(auth03_clusterid,"AUTH2_03",msg="Auth2 clusterid({}) should be 'AUTH2_01',commands={}".format(auth03_clusterid,commands))
                self.assertEqual(session_cookie,auth03_session_key[:-2-16] + auth03_session_key[-2:],msg="Cluster session id should be populated from original session key.commands={}".format(commands))
                auth03_user_profile = res.json()
                self.assertEqual(auth03_user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth03_session_data = self.get_session_data(auth03_session_cookie,"auth03")
                self.assertEqual(auth03_session_data,session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth03_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth03_user_profile.items()))
                print("\n")

                #session has migrated from standalone server to cluster server,
                #it should be failed if try to use the original session to access standalone server
                res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile3 = res.json()
                self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands={}".format(commands))
                self.assertEqual(self.is_session_migrated(session_cookie,"standalone"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))
    
                res = requests.get(self.get_profile_url("standalone2"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile4 = res.json()
                self.assertEqual(user_profile4["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands={}".format(commands))
                self.assertEqual(self.is_session_migrated(session_cookie,"standalone2"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))

                res = requests.get(self.get_profile_url("auth02a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                user_profile5 = res.json()
                self.assertEqual(user_profile5["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands={}".format(commands))

                auth02_session_cookie = self.get_cluster_session_cookie("AUTH2_02",auth03_session_cookie)
                self.assertEqual(self.is_session_migrated(session_cookie,"auth02a"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))

                #try to migrate the standalone session to cluster server again.
                res = requests.get(self.get_profile_url("auth03"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
                res.raise_for_status()
                auth03_session_cookie2 = res.cookies[settings.SESSION_COOKIE_NAME]
                self.assertEqual(auth03_session_cookie2,auth03_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.commands={}".format(commands))
                auth03_user_profile2 = res.json()
                self.assertEqual(auth03_user_profile2["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth03_session_data2 = self.get_session_data(auth03_session_cookie2,"auth03")
                self.assertEqual(auth03_session_data2,session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,auth03_session_cookie2))
                print("\n")
    
            finally:
                self.shutdown_all_auth2_servers()
                pass
        
    def test_migrate_session_among_clusters(self):
        """
        Test the feature "migrate the session among clusters'
        """
        print("************Begin to run test case 'test_migrate_session_among_clusters'******************************")
        index = 0
        for commands in [
            {},
            {"auth01":"CACHE_KEY_PREFIX=auth01&&export CACHE_KEY_PREFIX"},
            {"auth02":"CACHE_KEY_PREFIX=auth02&&export CACHE_KEY_PREFIX"},
            {"auth01":"CACHE_KEY_PREFIX=auth01&&export CACHE_KEY_PREFIX","auth02":"CACHE_KEY_PREFIX=auth02&&export CACHE_KEY_PREFIX"},
            {"auth01":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX","auth02":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX"},
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(commands))
            try:
                self.start_auth2_server("auth01",18060,precommands=commands.get("auth01"))
                self.start_auth2_server("auth02",18061,precommands=commands.get("auth02"))
    
                #login to auth01 to get a cluster session cookie
                auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_login_user_url("test_user01@test.com","auth01"),headers=self.cluster_headers)
                res.raise_for_status()
                auth01_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                returned_auth01_lb_hash_key,auth01_clusterid,auth01_session_key = auth01_session_cookie.split("|",2)
                self.assertEqual(returned_auth01_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as passed in lb hash key.commands=".format(commands))
                self.assertEqual(auth01_clusterid,"AUTH2_01",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth01'.commands=".format(commands))
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth01_user_profile = res.json()
                self.assertEqual(auth01_user_profile["authenticated"],True,msg="User should have already loged in.commands=".format(commands))
                auth01_session_data = self.get_session_data(auth01_session_cookie,"auth01")
                print("original session cookie = {}".format(auth01_session_cookie))
                print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile.items()))
    
                #migrate the session to 'auth02'
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_profile_url("auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth02_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                returned_auth02_lb_hash_key,auth02_clusterid,auth02_session_key = auth02_session_cookie.split("|",2)
                self.assertEqual(returned_auth02_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as lb session key in original sesion cookie.commands=".format(commands))
                self.assertEqual(auth02_clusterid,"AUTH2_02",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth02'.commands=".format(commands))
                self.assertEqual(auth02_session_key[:-2-16] + auth02_session_key[-2:],auth01_session_key[:-2-16] + auth01_session_key[-2:],msg="The random generated session key(not including the hash value of lb hash key and auth2 cluster id) should be the same value as the migrated session key.commands=".format(commands))
                auth02_user_profile = res.json()
                self.assertEqual(auth02_user_profile["authenticated"],True,msg="User should have already loged in.commands=".format(commands))
                auth02_session_data = self.get_session_data(auth02_session_cookie,"auth02")
                self.assertEqual(auth02_session_data,auth01_session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("migrated the auth01 sesesion cookie '{}' to auth02 session cookie  '{}'".format(auth01_session_cookie,auth02_session_cookie))
                print("\n")
    
                #session has migrated from auth01 to auth02
                #it should be failed if try to use the original session to access auth01
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth01_user_profile2 = res.json()
                self.assertEqual(auth01_user_profile2["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands=".format(commands))
                self.assertEqual(self.is_session_migrated(auth01_session_cookie,"auth01"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))
    
                #try to migrate the session from auth01 to auth02 again.
                res = requests.get(self.get_profile_url("auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth02_session_cookie2 = res.cookies[settings.SESSION_COOKIE_NAME]
                self.assertEqual(auth02_session_cookie2,auth02_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.commands=".format(commands))
                auth02_user_profile2 = res.json()
                self.assertEqual(auth02_user_profile2["authenticated"],True,msg="User should have already loged in.commands=".format(commands))
                auth02_session_data2 = self.get_session_data(auth02_session_cookie2,"auth02")
                self.assertEqual(auth02_session_data2,auth01_session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("\n")
    
                #migrate back to auth01
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth02_session_cookie})
                res.raise_for_status()
                auth01_user_profile3 = res.json()
                auth01_session_cookie3 = res.cookies[settings.SESSION_COOKIE_NAME]
                self.assertEqual(auth01_session_cookie3,auth01_session_cookie,msg="The session cookie of the migrated back session should be the same value as the original session cookie.commands=".format(commands))
                self.assertEqual(auth01_user_profile3["authenticated"],True,msg="User should have already loged in.commands=".format(commands))
                auth01_session_data3 = self.get_session_data(auth01_session_cookie3,"auth01")
                self.assertEqual(auth01_session_data3,auth01_session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("migrated the auth2 session cookie '{}' back to auth01 session cookie = {}".format(auth02_session_cookie,auth01_session_cookie3))
                print("\n")
    
                #session has migrated from auth02 to auth01
                #it should be failed if try to use the original session to access auth02
                res = requests.get(self.get_profile_url("auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth02_session_cookie})
                res.raise_for_status()
                auth02_user_profile3 = res.json()
                self.assertEqual(auth02_user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands=".format(commands))
                self.assertEqual(self.is_session_migrated(auth02_session_cookie,"auth02"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))
    
                #try to migrate the session from auth02 to auth01 again.
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth02_session_cookie})
                res.raise_for_status()
                auth01_user_profile4 = res.json()
                auth01_session_cookie4 = res.cookies[settings.SESSION_COOKIE_NAME]
                self.assertEqual(auth01_session_cookie4,auth01_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server.commands=".format(commands))
                self.assertEqual(auth01_user_profile4["authenticated"],True,msg="User should have already loged in.commands=".format(commands))
                auth01_session_data4 = self.get_session_data(auth01_session_cookie4,"auth01")
                self.assertEqual(auth01_session_data4,auth01_session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("\n")
    
            finally:
                self.shutdown_all_auth2_servers()
    
        
    def test_cluster_with_previous_cache(self):
        """
        Test the feature 'cluster with previous session cache enabled'
        """
        print("************Begin to run test case 'test_cluster_with_previous_cache'******************************")
        index = 0
        for commands in [
            {},
            {
                "auth01":"CACHE_KEY_PREFIX=auth01&&export CACHE_KEY_PREFIX",
                "auth01a":"PREVIOUS_CACHE_KEY_PREFIX=auth01&&export PREVIOUS_CACHE_KEY_PREFIX",
            },{
                "auth01a":"CACHE_KEY_PREFIX=auth01a&&export CACHE_KEY_PREFIX"
            },{
                "auth01":"CACHE_KEY_PREFIX=auth01&&export CACHE_KEY_PREFIX",
                "auth01a":"PREVIOUS_CACHE_KEY_PREFIX=auth01&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth01a&&export CACHE_KEY_PREFIX"
            },{
                "auth01":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX",
                "auth01a":"PREVIOUS_CACHE_KEY_PREFIX=auth2&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX"
            }
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(commands))

            try:
                #login to auth01 to get a cluster session cookie
                self.start_auth2_server("auth01",18060,precommands=commands.get("auth01"))
                auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_login_user_url("test_user01@test.com","auth01"),headers=self.cluster_headers)
                res.raise_for_status()
                auth01_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth01_user_profile = res.json()
                self.assertEqual(auth01_user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth01_session_data = self.get_session_data(auth01_session_cookie,"auth01")
                print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile.items()))
                print("\n")

                #auth01a's previous session cache is the session cache of cluster 'auth01'
                #Use session cookie to access auth01a to migrate the session from previous session cache to auth01a's session cache
                self.shutdown_auth2_server("auth01")
                self.start_auth2_server("auth01a",18060,precommands=commands.get("auth01a"))
                #use the session cookie to access auth01a to migrate the session from previous session cache to auth01a's session cache
                res = requests.get(self.get_profile_url("auth01a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                self.assertEqual(res.cookies.get(settings.SESSION_COOKIE_NAME),None,msg="Session is only migrated from previous session cache. and the client session cookie should not be changed..commands={}".format(commands))
                auth01a_user_profile = res.json()
                self.assertEqual(auth01a_user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth01a_session_data = self.get_session_data(auth01_session_cookie,"auth01a")
                self.assertEqual(auth01a_session_data,auth01_session_data,msg="Session data should not be changed during migration.commands={}".format(commands))
                print("\n".join("{}={}".format(k,v) for k,v in auth01a_user_profile.items()))
                print("\n")

                #session has migrated from previous cache, check whether the session in previous session cache is outdated.
                self.shutdown_auth2_server("auth01a")
                self.start_auth2_server("auth01",18060,precommands=commands.get("auth01"))
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth01_user_profile2 = res.json()
                self.assertEqual(auth01_user_profile2["authenticated"],False,msg="The session has been migrated from original session cache..commands={}".format(commands))
                self.assertEqual(self.is_session_migrated(auth01_session_cookie,"auth01"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))

            finally:
                self.shutdown_all_auth2_servers()
                pass
        
    def test_migrate_among_clusters_with_previous_cache(self):
        """
        Test the feature "migrate the session among clusters with previous session cache enabled'
        """
        print("************Begin to run test case 'test_migrate_among_clusters_with_previous_cache'******************************")
        index = 0
        for commands in [
            {},
            {
                "auth01":"CACHE_KEY_PREFIX=auth01&&export CACHE_KEY_PREFIX",
                "auth01a":"PREVIOUS_CACHE_KEY_PREFIX=auth01&&export PREVIOUS_CACHE_KEY_PREFIX",
            },{
                "auth01a":"CACHE_KEY_PREFIX=auth01a&&export CACHE_KEY_PREFIX",
                "auth03":"CACHE_KEY_PREFIX=auth03&&export CACHE_KEY_PREFIX"
            },{
                "auth01":"CACHE_KEY_PREFIX=auth01&&export CACHE_KEY_PREFIX",
                "auth01a":"PREVIOUS_CACHE_KEY_PREFIX=auth01&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth01a&&export CACHE_KEY_PREFIX",
                "auth03":"CACHE_KEY_PREFIX=auth03&&export CACHE_KEY_PREFIX"
            },{
                "auth01":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX",
                "auth01a":"PREVIOUS_CACHE_KEY_PREFIX=auth2&&export PREVIOUS_CACHE_KEY_PREFIX&&CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX",
                "auth03":"CACHE_KEY_PREFIX=auth2&&export CACHE_KEY_PREFIX"
            }
        ]:
            index += 1
            if RUN_CASES > 0 and index > RUN_CASES:
                break
            print("========================================={}===========================================".format(commands))

            try:
                #login to auth01 to get a cluster session cookie
                self.start_auth2_server("auth01",18060,precommands=commands.get("auth01"))
                auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_login_user_url("test_user01@test.com","auth01"),headers=self.cluster_headers)
                res.raise_for_status()
                auth01_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                returned_auth01_lb_hash_key,auth01_clusterid,auth01_session_key = auth01_session_cookie.split("|",2)
                self.assertEqual(returned_auth01_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as lb session key in original sesion cookie.commands=".format(commands))
                self.assertEqual(auth01_clusterid,"AUTH2_01",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth02'.commands=".format(commands))
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth01_user_profile = res.json()
                self.assertEqual(auth01_user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth01_session_data = self.get_session_data(auth01_session_cookie,"auth01")
                print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile.items()))
                print("\n")

                #migrqte the session from auth01a to auth03
                self.shutdown_auth2_server("auth01")
                self.start_auth2_server("auth01a",18060,precommands=commands.get("auth01a"))
                self.start_auth2_server("auth03",18061,precommands=commands.get("auth03"))
                self.cluster_headers["X-LB-HASH-KEY"] = auth01_lb_hash_key
                res = requests.get(self.get_profile_url("auth03"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth03_user_profile = res.json()
                auth03_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
                returned_auth03_lb_hash_key,auth03_clusterid,auth03_session_key = auth03_session_cookie.split("|",2)
                self.assertEqual(returned_auth03_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as lb session key in original sesion cookie.commands=".format(commands))
                self.assertEqual(auth03_clusterid,"AUTH2_03",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth02'.commands=".format(commands))
                self.assertEqual(auth03_session_key[:-2-16] + auth03_session_key[-2:],auth01_session_key[:-2-16] + auth01_session_key[-2:],msg="The random generated session key(not including the hash value of lb hash key and auth2 cluster id) should be the same value as the migrated session key.commands=".format(commands))
                self.assertEqual(auth03_user_profile["authenticated"],True,msg="User should have already loged in.commands={}".format(commands))
                auth03_session_data = self.get_session_data(auth03_session_cookie,"auth03")
                self.assertEqual(auth03_session_data,auth01_session_data,msg="Session data should not be changed during migration.commands={}".format(commands))

                #session has migrated from previous cache, check whether it is invalidated in the original session cache
                res = requests.get(self.get_profile_url("auth01a"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth01a_user_profile2 = res.json()
                self.assertEqual(auth01a_user_profile2["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands={}".format(commands))
                self.assertEqual(self.is_session_migrated(auth01_session_cookie,"auth01a"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))

                self.shutdown_auth2_server("auth01a")
                self.start_auth2_server("auth01",18060,precommands=commands.get("auth01"))
                res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
                res.raise_for_status()
                auth01_user_profile3 = res.json()
                self.assertEqual(auth01_user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore.commands={}".format(commands))
                self.assertEqual(self.is_session_migrated(auth01_session_cookie,"auth01"),True,msg="The migrated session data should be '{{\"migrated\":True}}'.commands={}".format(commands))

            finally:
                self.shutdown_all_auth2_servers()
                pass
        
