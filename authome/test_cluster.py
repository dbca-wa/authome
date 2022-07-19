import requests

from django.conf import settings
from django.test import TestCase
from django.utils import timezone

from . import utils
from . import testutils


class ClusterTestCase(testutils.StartServerMixin,TestCase):
    def atest_migrate_to_default_cluster(self):
        try:
            #login to a standalone server first
            self.start_auth2_server("standalone",18060)
            res = requests.get(self.get_login_user_url("test_user01@test.com","standalone"),headers=self.headers)
            res.raise_for_status()
            session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
            res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
            res.raise_for_status()
            user_profile = res.json()
            self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in")
            print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))
            print("\n")

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
            print("\n".join("{}={}".format(k,v) for k,v in user_profile2.items()))
            print("\n")

            #session has migrated from standalone server to cluster server,
            #it should be failed if try to use the original session to access standalone server
            res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
            res.raise_for_status()
            user_profile3 = res.json()
            self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore")

            #try to migrate the standalone session to cluster server again.
            res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
            res.raise_for_status()
            cluster_session_cookie2 = res.cookies[settings.SESSION_COOKIE_NAME]
            self.assertEqual(cluster_session_cookie2,cluster_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server")
            user_profile4 = res.json()
            print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,cluster_session_cookie))
            print("\n".join("{}={}".format(k,v) for k,v in user_profile4.items()))
            print("\n")


        finally:
            self.shutdown_all_auth2_servers()

        pass
        
    def test_migrate_to_other_cluster(self):
        try:
            #login to a standalone server first
            self.start_auth2_server("standalone",18060)
            res = requests.get(self.get_login_user_url("test_user01@test.com","standalone"),headers=self.headers)
            res.raise_for_status()
            session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
            res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
            res.raise_for_status()
            user_profile = res.json()
            self.assertEqual(user_profile["authenticated"],True,msg="User should have already loged in")
            print("\n".join("{}={}".format(k,v) for k,v in user_profile.items()))

            #migrate to cluster server
            self.start_auth2_server("auth01",18061)
            self.start_auth2_server("auth02",18062)
            lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
            self.cluster_headers["X-hash-key"] = lb_hash_key
            res = requests.get(self.get_profile_url("auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
            res.raise_for_status()
            cluster_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
            returned_lb_hash_key,auth2_cluster,session_key = cluster_session_cookie.split("|",2)
            self.assertEqual(lb_hash_key,returned_lb_hash_key,msg="Hash key in session cookie should have the same value as the request header 'X-hash-key'")
            self.assertEqual(auth2_cluster,"AUTH2_02",msg="Auth2 clusterid({}) should be 'AUTH2_01'".format(auth2_cluster))
            self.assertEqual(session_cookie,session_key[:-2-16] + session_key[-2:],msg="Cluster session id should be populated from original session key")
            user_profile2 = res.json()
            print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,cluster_session_cookie))
            print("\n".join("{}={}".format(k,v) for k,v in user_profile2.items()))



            #session has migrated from standalone server to cluster server,
            #it should be failed if try to use the original session to access standalone server
            res = requests.get(self.get_profile_url("standalone"),headers=self.headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
            res.raise_for_status()
            user_profile3 = res.json()
            self.assertEqual(user_profile3["authenticated"],False,msg="The original session has been migrated, can't use it to access anymore")

            #try to migrate the standalone session to cluster server again.
            res = requests.get(self.get_profile_url("auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie})
            res.raise_for_status()
            cluster_session_cookie2 = res.cookies[settings.SESSION_COOKIE_NAME]
            self.assertEqual(cluster_session_cookie2,cluster_session_cookie,msg="The session cookie should be the same no matter how many times a session is migrated to the same cluster server")
            user_profile4 = res.json()
            print("Succeed to migrate the session key({}) to cluster enabled session key({})".format(session_cookie,cluster_session_cookie))
            print("\n".join("{}={}".format(k,v) for k,v in user_profile4.items()))
            print("\n")

        finally:
            self.shutdown_all_auth2_servers()

        pass

    def atest_migrate_session_among_clusters(self):
        try:
            #migrate to cluster server
            self.start_auth2_server("auth01",18060)
            self.start_auth2_server("auth02",18061)

            #login to auth01
            auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
            self.cluster_headers["X-hash-key"] = auth01_lb_hash_key
            res = requests.get(self.get_login_user_url("test_user01@test.com","auth01"),headers=self.cluster_headers)
            res.raise_for_status()
            auth01_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
            returned_auth01_lb_hash_key,auth01_cluster,auth01_session_key = auth01_session_cookie.split("|",2)
            self.assertEqual(returned_auth01_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as passed in lb hash key")
            self.assertEqual(auth01_cluster,"AUTH2_01",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth01'")
            res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
            res.raise_for_status()
            auth01_user_profile = res.json()
            self.assertEqual(auth01_user_profile["authenticated"],True,msg="User should have already loged in")
            print("original session cookie = {}".format(auth01_session_cookie))
            print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile.items()))

            auth02_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth02")
            self.cluster_headers["X-hash-key"] = auth02_lb_hash_key
            res = requests.get(self.get_profile_url("auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth01_session_cookie})
            res.raise_for_status()
            auth02_session_cookie = res.cookies[settings.SESSION_COOKIE_NAME]
            returned_auth02_lb_hash_key,auth02_cluster,auth02_session_key = auth02_session_cookie.split("|",2)
            self.assertEqual(returned_auth02_lb_hash_key,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as lb session key in original sesion cookie")
            self.assertEqual(auth02_cluster,"AUTH2_02",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth02'")
            self.assertEqual(auth02_session_key[:-2-16] + auth02_session_key[-2:],auth01_session_key[:-2-16] + auth01_session_key[-2:],msg="The random generated session key(not including the hash value of lb hash key and auth2 cluster id) should be the same value as the migrated session key.")
            res = requests.get(self.get_profile_url("auth02"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth02_session_cookie})
            res.raise_for_status()
            auth02_user_profile = res.json()
            print("migrated to auth02 session cookie = {}".format(auth02_session_cookie))
            print("\n".join("{}={}".format(k,v) for k,v in auth02_user_profile.items()))

            #migrate back to auth01
            auth01_lb_hash_key = "auth2_clusher_hash_key-{}".format("auth01")
            self.cluster_headers["X-hash-key"] = auth01_lb_hash_key
            res = requests.get(self.get_profile_url("auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:auth02_session_cookie})
            res.raise_for_status()
            auth01_user_profile2 = res.json()
            auth01_session_cookie2 = res.cookies[settings.SESSION_COOKIE_NAME]
            returned_auth01_lb_hash_key2,auth01_cluster2,auth01_session_key2 = auth01_session_cookie2.split("|",2)
            self.assertEqual(returned_auth01_lb_hash_key2,auth01_lb_hash_key,msg="Returned lb hash key in the session cookie should be the same value as lb session key in original sesion cookie")
            self.assertEqual(auth01_cluster2,"AUTH2_01",msg="Returned auth2 cluster name in the session cookie should be the same name as the cluster name of cluster 'auth01'")
            self.assertEqual(auth01_session_key2[:-2-16] + auth01_session_key2[-2:],auth02_session_key[:-2-16] + auth02_session_key[-2:],msg="The random generated session key(not including the hash value of lb hash key and auth2 cluster id) should be the same value as the migrated session key.")
            self.assertEqual(auth01_session_cookie2,auth01_session_cookie,msg="The session cookie of the migrated back session should be the same value as the original session cookie")
            print("migrated back to auth01 session cookie = {}".format(auth01_session_cookie2))
            print("\n".join("{}={}".format(k,v) for k,v in auth01_user_profile2.items()))

        finally:
            self.shutdown_all_auth2_servers()

        
