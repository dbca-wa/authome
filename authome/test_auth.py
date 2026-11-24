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
            ("all_user","gunfire.com","*",None),
            ("all_user","test.gunfire.com",None,'*')
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

        res = self.client.get(self.auth_url,domain="test.gunfire.com",url="/about")
        self.assertEqual(res.status_code,403,msg="Should return 403 response for non-authorized request")

        for i in range(0,5):
            res = self.client.get(self.auth_url,domain="gunfire.com",url="/about")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
 
    def test_auth_optional(self):
        self.test_users = [
            ("staff_2@gunfire.com","staff_2@gunfire.com")
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","gunfire.com","*",None),
            ("all_user","test.gunfire.com",None,'*')
        ]
        self.populate_testdata()

        #test sso_auth without authentication  
        res = self.client.get(self.auth_optional_url)
        self.assertEqual(res.status_code,204,msg="Should return 204 response for unauthenticated request")
        
        #test sso_auth after authentication   
        self.client.force_login(self.test_users["staff_2@gunfire.com"])
        res = self.client.get(self.auth_optional_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

        for i in range(0,5):
            res = self.client.get(self.auth_optional_url,url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
 
        #although test.gunfire.com is not allowed by authorization, but auth_optional has high priority, authorizatoin rules will not be check.
        for i in range(0,5):
            res = self.client.get(self.auth_optional_url,url="https://test.gunfire.com/about")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
 
    def test_auth_basic(self):
        self.test_users = [
            ("staff_3@gunfire.com","staff_3@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","gunfire.com","*",None),
            ("all_user","test.gunfire.com",None,'*')
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_basic_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")

        #test sso token auth
        try:
            user=self.test_users["staff_3@gunfire.com"]
            for username,token in ((user.username,user.token.token),(user.email,user.token.token)):
                res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
                self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
                self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
        
                res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://test.gunfire.com/")
                self.assertEqual(res.status_code,403,msg="Should return 403 response for non-authorized request")

                for i in range(0,5):
                    res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://gunfire.com/")
                    self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
                    self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
    
                #test the flag CHECK_AUTH_BASIC_PER_REQUEST
                settings.CHECK_AUTH_BASIC_PER_REQUEST = False
                #change the token to invalid the current token
                user.token.token += "!"
                user.token.save()
                #use the previous token to test. because CHECK_AUTH_BASIC_PER_REQUEST is False, auth2 shoule pass the authentication
                res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://gunfire.com/")
                self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request because the token was changed and but CHECK_AUTH_BASIC_PER_REQUEST is False")
                self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

                settings.CHECK_AUTH_BASIC_PER_REQUEST = True
                #use the previous token to test. because CHECK_AUTH_BASIC_PER_REQUEST is True, auth2 shoule not pass the authentication
                #the cached response should be removed.
                res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://gunfire.com/")
                self.assertEqual(res.status_code,401,msg="Should return 401 response for authenticated request because the token was changed and CHECK_AUTH_BASIC_PER_REQUEST is True")

                #rollback the token
                user.token.token = user.token.token[:-1]
                user.token.save()
                res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://gunfire.com/")
                self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
                self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

                res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://gunfire.com/")
                self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
                self.assertEqual(res.has_header('X-auth-cache-hit'),True,msg="Should authenticate the user without hit the cache")

                #the cached response should be removed after the fake token
                res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,"faketoken"))
                self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")

        finally:
            pass

    def test_auth_basic_optional(self):
        self.test_users = [
            ("staff_4@gunfire.com","staff_4@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","gunfire.com","*",None),
            ("all_user","test.gunfire.com",None,'*')
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_basic_optional_url)
        self.assertEqual(res.status_code,204,msg="Should return 204 response for unauthenticated request")
        
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")

        #test sso token auth
        user=self.test_users["staff_4@gunfire.com"]
        for username,token in ((user.username,user.token.token),(user.email,user.token.token)):
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
    
            for i in range(0,5):
                res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token),url="https://gunfire.com/")
                self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
                self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            #although test.gunfire.com is not allowed by authorization, but auth_basic_optional has high priority, authorizatoin rules will not be check.
            for i in range(0,5):
                res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token),url="https://test.gunfire.com/")
                self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,"faketoken"))
            self.assertEqual(res.status_code,204,msg="Should return 204 response for unauthenticated request")

    def test_auth_basic_over_auth(self):
        self.test_users = [
            ("staff_5@gunfire.com","staff_5@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","gunfire.com","*",None),
            ("all_user","test.gunfire.com",None,'*')
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        #test sso_auth after authentication   
        self.client.force_login(self.test_users["staff_5@gunfire.com"])
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")

        res = self.client.get(self.auth_url,url="https://gunfire.com")
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

        res = self.client.get(self.auth_url,url="https://test.gunfire.com")
        self.assertEqual(res.status_code,403,msg="Should return 403 response for non-authorized request")

        #test sso token auth
        user=self.test_users["staff_5@gunfire.com"]
        for username,token in ((user.username,user.token.token),(user.email,user.token.token)):
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
    
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://test.gunfire.com")
            self.assertEqual(res.status_code,403,msg="Should return 403 response for non-authorized request")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,"faketoken"),url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,"faketoken"),url="https://test.gunfire.com")
            self.assertEqual(res.status_code,403,msg="Should return 403 response for non-authorized request")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,"faketoken"),url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")


    def test_auth_basic_optional_over_auth(self):
        self.test_users = [
            ("staff_5@gunfire.com","staff_5@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","gunfire.com","*",None),
            ("all_user","test.gunfire.com",None,'*')
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        res = self.client.get(self.auth_basic_optional_url,url="https://gunfire.com")
        self.assertEqual(res.status_code,204,msg="Should return 204 response for non-authenticated request")
    
        res = self.client.get(self.auth_basic_optional_url,url="https://test.gunfire.com")
        self.assertEqual(res.status_code,204,msg="Should return 204 response for non-authenticated request")
    
        #test sso_auth after authentication   
        self.client.force_login(self.test_users["staff_5@gunfire.com"])

        res = self.client.get(self.auth_url,url="https://test.gunfire.com")
        self.assertEqual(res.status_code,403,msg="Should return 403 response for non-authorized request")

        res = self.client.get(self.auth_url,url="https://gunfire.com")
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")

        res = self.client.get(self.auth_basic_optional_url,url="https://gunfire.com")
        self.assertEqual(res.status_code,200,msg="Should return 204 response for non-authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
    
        res = self.client.get(self.auth_basic_optional_url,url="https://test.gunfire.com")
        self.assertEqual(res.status_code,200,msg="Should return 204 response for non-authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
    
        #test sso token auth
        user=self.test_users["staff_5@gunfire.com"]
        for username,token in ((user.username,user.token.token),(user.email,user.token.token)):
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token),url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
    
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token),url="https://test.gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token),url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,"faketoken"),url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,"faketoken"),url="https://test.gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,"faketoken"),url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

    def test_auth_basic_over_auth_with_different_user(self):
        self.test_users = [
            ("staff_6@gunfire.com","staff_6@gunfire.com",False),
            ("staff_7@gunfire.com","staff_7@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","gunfire.com","*",None),
            ("all_user","test.gunfire.com",None,'*')
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        #test sso_auth after authentication   
        user1=self.test_users["staff_6@gunfire.com"]
        self.client.force_login(user1)
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")

        res = self.client.get(self.auth_url,url="https://test.gunfire.com/about")
        self.assertEqual(res.status_code,403,msg="Should return 403 response for non-authorized request")

        res = self.client.get(self.auth_url,url="https://gunfire.com/about")
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

        #test sso token auth
        user2=self.test_users["staff_7@gunfire.com"]
        for username,token in ((user2.username,user2.token.token),(user2.email,user2.token.token)):
        #for username,token in ((user2.username,user2.token.token),):
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
            self.assertEqual(res.get('X-email'),user2.email,msg="Should authenticate the user({})".format(user2.email))
    
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://test.gunfire.com")
            self.assertEqual(res.status_code,403,msg="Should return 403 response for non-authorized request")

            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,token),url="https://gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            self.assertEqual(res.get('X-email'),user2.email,msg="Should authenticate the user({})".format(user2.email))
    
            res = self.client.get(self.auth_basic_url,authorization=self.basic_auth(username,"faketoken"))
            self.assertEqual(res.status_code,401,msg="Should return 401 response for request with invalid token")

    def test_auth_basic_optional_over_auth_with_different_user(self):
        self.test_users = [
            ("staff_6@gunfire.com","staff_6@gunfire.com",False),
            ("staff_7@gunfire.com","staff_7@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","gunfire.com","*",None),
            ("all_user","test.gunfire.com",None,'*')
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        #test sso_auth after authentication   
        user1=self.test_users["staff_6@gunfire.com"]
        self.client.force_login(user1)
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")

        res = self.client.get(self.auth_url,url="https://test.gunfire.com/about")
        self.assertEqual(res.status_code,403,msg="Should return 403 response for non-authorized request")

        res = self.client.get(self.auth_url,url="https://gunfire.com/about")
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

        #test sso token auth
        user2=self.test_users["staff_7@gunfire.com"]
        for username,token in ((user2.username,user2.token.token),(user2.email,user2.token.token)):
        #for username,token in ((user2.username,user2.token.token),):
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hitting the cache")
            self.assertEqual(res.get('X-email'),user2.email,msg="Should authenticate the user({})".format(user2.email))
    
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token),url="https://test.gunfire.com")
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),True,msg="Should authenticate the user with hitting the cache")
            self.assertEqual(res.get('X-email'),user2.email,msg="Should authenticate the user({})".format(user2.email))

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,"faketoken"))
            self.assertEqual(res.status_code,204,msg="Should return 204 response for request with invalid token")

    def test_auth_basic_cache(self):
        self.test_users = [
            ("staff_8@gunfire.com","staff_8@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        settings.CHECK_AUTH_BASIC_PER_REQUEST = False
        #test sso token auth
        user=self.test_users["staff_8@gunfire.com"]
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

    def test_auth_basic_optional_cache(self):
        self.test_users = [
            ("staff_8@gunfire.com","staff_8@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        settings.CHECK_AUTH_BASIC_PER_REQUEST = False
        #test sso token auth
        user=self.test_users["staff_8@gunfire.com"]
        for username,usertoken in ((user.username,user.token),):
            token = usertoken.token
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.enabled = False
            usertoken.save()

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")
            
            cache.clean_auth_cache(True)
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,204,msg="Should return 204 response because user's token was disabled")
            
            usertoken.enabled = True
            usertoken.save()
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.expired = timezone.localdate() - timedelta(days=1)
            usertoken.save()

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            cache.clean_auth_cache(True)
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,204,msg="Should return 204 response because user's token was expired")

            usertoken.expired = timezone.localdate() + timedelta(days=1)
            usertoken.save()

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.token = None
            usertoken.save()
            
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            cache.clean_auth_cache(True)
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,204,msg="Should return 204 response because user's token was cleared")

            usertoken.token = token
            usertoken.save()
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was restored")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.generate_token()
            usertoken.save()

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            cache.clean_auth_cache(True)
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,204,msg="Should return 204 response because user's token was regenerated")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
    
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth("invalid-{}".format(username),usertoken.token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,204,msg="Should return 204 response because user's token was regenerated")


    def test_check_auth_basic_per_request(self):
        settings.CHECK_AUTH_BASIC_PER_REQUEST = True
        self.test_users = [
            ("staff_9@gunfire.com","staff_9@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso token auth
        user=self.test_users["staff_9@gunfire.com"]
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

    def test_check_auth_basic_optional_per_request(self):
        settings.CHECK_AUTH_BASIC_PER_REQUEST = True
        self.test_users = [
            ("staff_9@gunfire.com","staff_9@gunfire.com",True)
        ]
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso token auth
        user=self.test_users["staff_9@gunfire.com"]
        for username,usertoken in ((user.username,user.token),):
            token = usertoken.token
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.enabled = False
            usertoken.save()
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,204,msg="Should return 204 response because user's token was regenerated")
            
            usertoken.enabled = True
            usertoken.save()
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was enabled")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.expired = timezone.localdate() - timedelta(days=1)
            usertoken.save()
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,204,msg="Should return 204 response because user's token was regenerated")

            usertoken.expired = timezone.localdate() + timedelta(days=1)
            usertoken.save()
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because user's token was extended")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.token = None
            usertoken.save()
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,204,msg="Should return 204 response because user's token was regenerated")

            usertoken.token = token
            usertoken.save()
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.status_code,200,msg="Should return 401 response because user's token was resaved")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

            usertoken.generate_token()
            usertoken.save()
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,204,msg="Should return 204 response because user's token was regenerated")

            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
    
            res = self.client.get(self.auth_basic_optional_url,authorization=self.basic_auth(username,usertoken.token))
            self.assertEqual(res.status_code,200,msg="Should return 200 response because new token was used")
            self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

