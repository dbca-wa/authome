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
    def test_auth_cache_size(self):
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
            client = self.create_client()
            clients.append(client)
            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
            #test sso_auth after authentication   
            client.force_login(user)
            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")

            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

        for client in clients[-settings.AUTH_CACHE_SIZE:]:
            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

        for client in clients:
            res = client.get(self.auth_url)
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")

