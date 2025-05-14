# -*- coding: utf-8 -*-
from datetime import timedelta

from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from django.test import TestCase
from django.conf import settings

import base64

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access,UserToken
from .cache import cache
from .basetest import BaseAuthTestCase

class AuthTestCase(BaseAuthTestCase):
    def test_auth(self):
        self.test_users = [
            ("staff_1@gunfire.com","staff_1@gunfire.com")
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        #test sso_auth after authentication   
        self.client.force_login(self.test_users["staff_1@gunfire.com"])
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

        for i in range(0,5):
            res = self.client.get(self.auth_url,domain="gunfire.com",url="/about")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
 
    def test_auth_optional(self):
        self.test_users = [
            ("staff_1@gunfire.com","staff_1@gunfire.com")
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication  
        res = self.client.get(self.auth_optional_url)
        self.assertEqual(res.status_code,204,msg="Should return 204 response for unauthenticated request")
        
        #test sso_auth after authentication   
        self.client.force_login(self.test_users["staff_1@gunfire.com"])
        res = self.client.get(self.auth_optional_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

        for i in range(0,5):
            res = self.client.get(self.auth_optional_url,domain="gunfire.com",url="/about")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
 
    def test_auth_basic(self):
        self.test_users = [
            ("staff_1@gunfire.com","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_basic_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")

        #test sso token auth
        user=self.test_users["staff_1@gunfire.com"]
        for username,token in ((user.username,user.token.token),(user.email,user.token.token)):
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
    
            for i in range(0,5):
                res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
                self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
                self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,"faketoken"))
            self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")

    def test_auth_basic_optional(self):
        self.test_users = [
            ("staff_1@gunfire.com","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_basic_optional_url)
        self.assertEqual(res.status_code,204,msg="Should return 204 response for unauthenticated request")
        
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")

        #test sso token auth
        user=self.test_users["staff_1@gunfire.com"]
        for username,token in ((user.username,user.token.token),(user.email,user.token.token)):
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
    
            for i in range(0,5):
                res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
                self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
                self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,"faketoken"))
            self.assertEqual(res.status_code,204,msg="Should return 204 response for unauthenticated request")

    def test_auth_basic_over_auth(self):
        self.test_users = [
            ("staff_1@gunfire.com","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        #test sso_auth after authentication   
        self.client.force_login(self.test_users["staff_1@gunfire.com"])
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")

        res = self.client.get(self.auth_url,domain="gunfire.com",url="/about")
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

        #test sso token auth
        user=self.test_users["staff_1@gunfire.com"]
        for username,token in ((user.username,user.token.token),(user.email,user.token.token)):
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
    
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,"faketoken"))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")


    def test_auth_basic_over_auth_with_different_user(self):
        self.test_users = [
            ("staff_1@gunfire.com","staff_1@gunfire.com",False),
            ("staff_2@gunfire.com","staff_2@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        #test sso_auth after authentication   
        user1=self.test_users["staff_1@gunfire.com"]
        self.client.force_login(user1)
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")

        res = self.client.get(self.auth_url,domain="gunfire.com",url="/about")
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

        #test sso token auth
        user2=self.test_users["staff_2@gunfire.com"]
        for username,token in ((user2.username,user2.token.token),(user2.email,user2.token.token)):
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
            self.assertEqual(res.get('X-email'),user2.email,msg="Should authenticate the user({})".format(user2.email))
    
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            self.assertEqual(res.get('X-email'),user2.email,msg="Should authenticate the user({})".format(user2.email))
    
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,"faketoken"))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            self.assertEqual(res.get('X-email'),user1.email,msg="Should fallback to session authentication.  authenticated user = {}".format(user1.email))


    def test_auth_basic_negative(self):
        self.test_users = [
            ("staff_1@gunfire.com","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso token auth
        user=self.test_users["staff_1@gunfire.com"]
        for username,usertoken in ((user.username,user.token),):
            token = usertoken.token
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.enabled = False
            usertoken.save()

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            
            cache.clean_auth_cache(True)
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was disabled")
            
            usertoken.enabled = True
            usertoken.save()
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.expired = timezone.localdate() - timedelta(days=1)
            usertoken.save()

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            cache.clean_auth_cache(True)
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was expired")

            usertoken.expired = timezone.localdate() + timedelta(days=1)
            usertoken.save()

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.token = None
            usertoken.save()
            
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            cache.clean_auth_cache(True)
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was cleared")

            usertoken.token = token
            usertoken.save()
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was restored")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.generate_token()
            usertoken.save()

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            cache.clean_auth_cache(True)
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was regenerated")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
    
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth("invalid-{}".format(username),usertoken.token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was regenerated")


    def test_check_auth_basic_per_request(self):
        settings.CHECK_AUTH_BASIC_PER_REQUEST = True
        self.test_users = [
            ("staff_1@gunfire.com","staff_1@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso token auth
        user=self.test_users["staff_1@gunfire.com"]
        for username,usertoken in ((user.username,user.token),):
            token = usertoken.token
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.enabled = False
            usertoken.save()
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was disabled")
            
            usertoken.enabled = True
            usertoken.save()
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.expired = timezone.localdate() - timedelta(days=1)
            usertoken.save()
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was expired")

            usertoken.expired = timezone.localdate() + timedelta(days=1)
            usertoken.save()
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.token = None
            usertoken.save()
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was cleared")

            usertoken.token = token
            usertoken.save()
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.generate_token()
            usertoken.save()
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,401,msg="Should return 401 response because user's token was regenerated")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
    
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

