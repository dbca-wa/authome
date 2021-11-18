import time
from datetime import timedelta
# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
from django.urls import reverse
from django.test import TestCase, Client
from django.conf import settings
from django.utils import timezone

import base64

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access,UserToken
from .cache import cache
from .basetest import BaseAuthCacheTestCase

class AuthCacheTestCase(BaseAuthCacheTestCase):

    def test_auth_cache_size(self):
        self.test_users = [
            ("staff_1","staff_1@gunfire.com",True),
            ("staff_2","staff_2@gunfire.com",True),
            ("staff_3","staff_3@gunfire.com",True),
            ("staff_4","staff_4@gunfire.com",True),
            ("staff_5","staff_5@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
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

    def test_auth_basic_cache_size(self):
        self.test_users = [
            ("staff_1","staff_1@gunfire.com",True),
            ("staff_2","staff_2@gunfire.com",True),
            ("staff_3","staff_3@gunfire.com",True),
            ("staff_4","staff_4@gunfire.com",True),
            ("staff_5","staff_5@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
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
            res = client.get(self.auth_basic_url)
            self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
            #test sso_auth after authentication   
            token = user.token.token
            res = client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")

            res = client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        for user,client in clients[-settings.AUTH_CACHE_SIZE:]:
            username = user.username
            token = user.token.token
            res = client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        for user,client in clients:
            username = user.username
            token = user.token.token
            res = client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
            self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

    def test_auth_cache_expire(self):
        self.test_users = [
            ("staff_1","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
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

    def test_auth_basic_cache_expire(self):
        self.test_users = [
            ("staff_1","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
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
        res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        print("Waiting {} seconds to expire the auth cache data".format(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds + 1))
        time.sleep(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds + 1)

        res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

        res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
        self.assertEqual(res.get('X-email'),user.email,msg="Should authenticate the user({})".format(user.email))

    def test_auth_basic_negative(self):
        self.test_users = [
            ("staff_1","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso token auth
        user=self.test_users["staff_1"]
        for username,usertoken in ((user.username,user.token),(user.email,user.token)):
            token = usertoken.token
            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.enabled = False
            usertoken.save()

            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            print("Waiting {} seconds to expire the auth cache data".format(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds))
            time.sleep(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds)
            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was disabled")
            
            usertoken.enabled = True
            usertoken.save()
            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")

            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.expired = timezone.now() - timedelta(days=1)
            usertoken.save()

            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            print("Waiting {} seconds to expire the auth cache data".format(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds))
            time.sleep(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds)
            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was expired")

            usertoken.expired = timezone.now() + timedelta(days=1)
            usertoken.save()
            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")

            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.token = None
            usertoken.save()

            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            print("Waiting {} seconds to expire the auth cache data".format(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds))
            time.sleep(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds)
            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was cleared")

            usertoken.token = token
            usertoken.save()
            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")

            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.generate_token()
            usertoken.save()

            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            print("Waiting {} seconds to expire the auth cache data".format(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds))
            time.sleep(settings.AUTH_BASIC_CACHE_EXPIRETIME.seconds )
            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was regenerated")

            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
    
            res = self.client.get(self.auth_basic_url,HTTP_AUTHORIZATION=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
