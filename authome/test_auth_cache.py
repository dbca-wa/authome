import time
# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
from django.urls import reverse
from django.test import TestCase, Client
from django.conf import settings

import base64

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access,UserToken
from .cache import cache
from .basetest import BaseAuthTestCase

class AuthCacheTestCase(BaseAuthTestCase):
    def tes1t_auth_cache_size(self):
        self.test_users = [
            ("staff_1","staff_1@gunfire.com",True),
            ("staff_2","staff_2@gunfire.com",True),
            ("staff_3","staff_3@gunfire.com",True),
            ("staff_4","staff_4@gunfire.com",True),
            ("staff_5","staff_5@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        clients = []
        users = []
        for username,user in self.test_users.items():
            client = self.create_client()
            clients.append((user,client))
            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
            #test sso_auth after authentication   
            client.force_login(user)
            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        for user,client in clients[-settings.AUTH_CACHE_SIZE:]:
            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        for user,client in clients:
            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

    def tes1t_auth_token_cache_size(self):
        self.test_users = [
            ("staff_1","staff_1@gunfire.com",True),
            ("staff_2","staff_2@gunfire.com",True),
            ("staff_3","staff_3@gunfire.com",True),
            ("staff_4","staff_4@gunfire.com",True),
            ("staff_5","staff_5@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        clients = []
        for username,user in self.test_users.items():
            client = self.client
            clients.append((user,client))
            res = client.get(self.auth_token_url)
            self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
            #test sso_auth after authentication   
            token = user.token.token
            res = client.get(self.auth_token_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")

            res = client.get(self.auth_token_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        for user,client in clients[-settings.AUTH_CACHE_SIZE:]:
            username = user.username
            token = user.token.token
            res = client.get(self.auth_token_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        for user,client in clients:
            username = user.username
            token = user.token.token
            res = client.get(self.auth_token_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

    def test_auth_cache_expire(self):
        self.test_users = [
            ("staff_1","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        clients = []
        user = self.test_users["staff_1"]
        self.client.force_login(user)
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        print("Waiting {} seconds to expire the auth cache data".format(settings.AUTH_CACHE_EXPIRETIME.seconds + 1))
        time.sleep(settings.AUTH_CACHE_EXPIRETIME.seconds + 1)

        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

    def test_auth_token_cache_expire(self):
        self.test_users = [
            ("staff_1","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        clients = []
        user = self.test_users["staff_1"]
        username = user.username
        token = user.token.token
        res = self.client.get(self.auth_token_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        res = self.client.get(self.auth_token_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        print("Waiting {} seconds to expire the auth cache data".format(settings.AUTH_TOKEN_CACHE_EXPIRETIME.seconds + 1))
        time.sleep(settings.AUTH_TOKEN_CACHE_EXPIRETIME.seconds + 1)

        res = self.client.get(self.auth_token_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        res = self.client.get(self.auth_token_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

