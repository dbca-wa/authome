import traceback
import time
import random
import json
import socket
import requests
import json
from datetime import datetime,timedelta

from django.test import TestCase
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY
from django.contrib.auth import BACKEND_SESSION_KEY,HASH_SESSION_KEY
from django.utils import timezone
from django.conf import settings

from . import urls

from . import cachesessionstore
from .utils import env
from . import models
from .cache import cache,get_usercache
from authome import performance


class RequestHeaderTestCase(TestCase):
    TESTED_SERVER = env("TESTED_SERVER",default="http://127.0.0.1:8080")
    TESTUSERID = env("TEST_USERID")

    profile_url = "{}/sso/profile".format(TESTED_SERVER)
    noauth_url = "{}/echo".format(TESTED_SERVER)
    auth_url = "{}/echo/auth".format(TESTED_SERVER)
    auth_basic_url = "{}/echo/auth_basic".format(TESTED_SERVER)
    auth_optional_url = "{}/echo/auth_optional".format(TESTED_SERVER)

    @classmethod
    def setUpClass(cls):

        cls.usersession = cachesessionstore.SessionStore()
        cls.usersession[USER_SESSION_KEY] = str(cls.TESTUSERID)
        cls.usersession[BACKEND_SESSION_KEY] = "django.contrib.auth.backends.ModelBackend"
        cls.usersession[HASH_SESSION_KEY] = ""
        cls.usersession["session_timeout"] = 3600
        cls.usersession.save()

        cls.sso_headers = {"remote-user":"email","x-email":"email","x-first-name":"first_name","x-last-name":"last_name","x-groups":"groups"}
        cls.user_sso_headers = {}
        res = requests.get(cls.profile_url,cookies={settings.SESSION_COOKIE_NAME:cls.usersession.session_key}).json()
        for k,v in cls.sso_headers.items():
            cls.user_sso_headers[k] = res[v]

        cls.testuser = models.User(id=cls.TESTUSERID,email=res["email"],first_name=res["first_name"],last_name=res["last_name"])
        cls.testusertoken = models.UserToken(user=cls.testuser,token=res["access_token"])

        cls.injected_headers = {
            "remote-user": "fakeuser.hacker@dbca.wa.gov.au",
            "x-email":"fakeuser.hacker@dbca.wa.gov.au",
            "x-first-name": "fakeuser",
            "x-last-name": "hacker",
            "x-groups": "public,staff",
            "x-test": "test"
        }

    @classmethod
    def tearDownClass(cls):
        cls.usersession.delete()
        usercache = get_usercache(cls.testuser.id)
        usercache.delete(settings.GET_USER_KEY(cls.testuser.id))
        usercache.delete(settings.GET_USERTOKEN_KEY(cls.testuser.id))
        cls.testusertoken.delete()
        cls.testuser.delete()
        
    def _post_teardown(self):
        pass

    def test_noauth(self):
        cls = self.__class__

        res = requests.get(cls.noauth_url,headers=cls.injected_headers).json()
        res_headers = res.get("headers",{})
        sso_headers = []
        other_headers = []
        for k,v in cls.injected_headers.items():
            if k.lower() in cls.sso_headers:
                if k.lower() in res_headers:
                    sso_headers.append("{}={}".format(k,res_headers[k.lower()]))
            elif v != res_headers.get(k.lower()):
                other_header.append("{}={}(expected {})".format(k,res_headers.get(k.lower()),v))

        self.assertEqual(len(sso_headers),0,msg="SSO headers({}) were injected".format(" , ".join(sso_headers)))
        self.assertEqual(len(other_headers),0,msg="Other headers({}) were changed".format(" , ".join(other_headers)))

    def test_auth(self):
        cls = self.__class__

        res = requests.get(cls.auth_url,headers=cls.injected_headers,cookies={settings.SESSION_COOKIE_NAME:cls.usersession.session_key}).json()
        res_headers = res.get("headers",{})
        sso_headers = []
        other_headers = []
        for k,v in cls.injected_headers.items():
            if k.lower() in cls.sso_headers:
                if res_headers.get(k.lower()) != cls.user_sso_headers[k]:
                    sso_headers.append("{}={}(expected {})".format(k,res_headers.get(k.lower()),cls.user_sso_headers[k]))
            elif v != res_headers.get(k.lower()):
                other_headers.append("{}={}(expected {})".format(k,res_headers.get(k.lower()),v))

        self.assertEqual(len(sso_headers),0,msg="SSO headers({}) were not properly set".format(" , ".join(sso_headers)))
        self.assertEqual(len(other_headers),0,msg="Other headers({}) were changed".format(" , ".join(other_headers)))

    def test_auth_optioal_without_auth(self):
        cls = self.__class__

        res = requests.get(cls.auth_optional_url,headers=cls.injected_headers).json()
        res_headers = res.get("headers",{})
        sso_headers = []
        other_headers = []
        for k,v in cls.injected_headers.items():
            if k.lower() in cls.sso_headers:
                if k.lower() in res_headers:
                    sso_headers.append("{}={}".format(k,res_headers[k.lower()]))
            elif v != res_headers.get(k.lower()):
                other_headers.append("{}={}(expected {})".format(k,res_headers.get(k.lower()),v))

        self.assertEqual(len(sso_headers),0,msg="SSO headers({}) were injected".format(" , ".join(sso_headers)))
        self.assertEqual(len(other_headers),0,msg="Other headers({}) were changed".format(" , ".join(other_headers)))

    def test_auth_optional(self):
        cls = self.__class__

        res = requests.get(cls.auth_optional_url,headers=cls.injected_headers,cookies={settings.SESSION_COOKIE_NAME:cls.usersession.session_key}).json()
        res_headers = res.get("headers",{})
        sso_headers = []
        other_headers = []
        for k,v in cls.injected_headers.items():
            if k.lower() in cls.sso_headers:
                if res_headers.get(k.lower()) != cls.user_sso_headers[k]:
                    sso_headers.append("{}={}(expected {})".format(k,res_headers.get(k.lower()),cls.user_sso_headers[k]))
            elif v != res_headers.get(k.lower()):
                other_headers.append("{}={}(expected {})".format(k,res_headers.get(k.lower()),v))

        self.assertEqual(len(sso_headers),0,msg="SSO headers({}) were not properly set".format(" , ".join(sso_headers)))
        self.assertEqual(len(other_headers),0,msg="Other headers({}) were changed".format(" , ".join(other_headers)))

    def test_auth_basic(self):
        cls = self.__class__

        res = requests.get(cls.auth_basic_url,headers=cls.injected_headers,auth=requests.auth.HTTPBasicAuth(cls.testuser.email, cls.testusertoken.token)).json()
        res_headers = res.get("headers",{})
        sso_headers = []
        other_headers = []
        for k,v in cls.injected_headers.items():
            if k.lower() in cls.sso_headers:
                if res_headers.get(k.lower()) != cls.user_sso_headers[k]:
                    sso_headers.append("{}={}(expected {})".format(k,res_headers.get(k.lower()),cls.user_sso_headers[k]))
            elif v != res_headers.get(k.lower()):
                other_headers.append("{}={}(expected {})".format(k,res_headers.get(k.lower()),v))

        self.assertEqual(len(sso_headers),0,msg="SSO headers({}) were not properly set".format(" , ".join(sso_headers)))
        self.assertEqual(len(other_headers),0,msg="Other headers({}) were changed".format(" , ".join(other_headers)))

