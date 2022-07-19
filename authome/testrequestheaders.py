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

from .utils import env
from . import models
from . import testutils


class RequestHeaderTestCase(testutils.StartServerMixin,TestCase):
    headers = {}
    cluster_headers = {}

    TESTED_SERVER = env("TESTED_SERVER")
    noauth_url = "/test/echo"
    auth_url = "/test/echo/auth"
    auth_basic_url = "/test/echo/auth_basic"
    auth_optional_url = "/test/echo/auth_optional"

    @classmethod
    def setUpClass(cls):
        #login to a standalone server first
        res = requests.get(cls.get_login_user_url("test_user01@test.com"),headers=cls.headers)
        res.raise_for_status()
        userprofile = res.json()
        cls.session_key = res.cookies[settings.SESSION_COOKIE_NAME]

        cls.sso_headers = {"remote-user":"email","x-email":"email","x-first-name":"first_name","x-last-name":"last_name","x-groups":"groups"}
        cls.user_sso_headers = {}
        res = requests.get(cls.get_profile_url("standalone"),cookies={settings.SESSION_COOKIE_NAME:cls.session_key}).json()
        for k,v in cls.sso_headers.items():
            cls.user_sso_headers[k] = res[v]


        cls.testuser = models.User(email="test_user01@test.com")
        cls.testusertoken = models.UserToken(user=cls.testuser,enabled=False if "access_token_error" in userprofile else True,token=userprofile["access_token"])

        cls.injected_headers = {
            "remote-user": "fakeuser.hacker@dbca.wa.gov.au",
            "x-email":"fakeuser.hacker@dbca.wa.gov.au",
            "x-first-name": "fakeuser",
            "x-last-name": "hacker",
            "x-groups": "public,staff",
            "x-test": "test"
        }
        for k,v in cls.headers.items():
            cls.injected_headers[k] = cls.headers[k]
    

    @classmethod
    def tearDownClass(cls):
        res = requests.get(cls.get_logout_url(),headers=cls.headers,cookies={settings.SESSION_COOKIE_NAME:cls.session_key},allow_redirects=False)
        res.raise_for_status()
        
    def _post_teardown(self):
        pass

    def test_noauth(self):
        cls = self.__class__
        res = requests.get(cls.get_absolute_url(cls.noauth_url),headers=cls.injected_headers).json()
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

        res = requests.get(cls.get_absolute_url(cls.auth_url),headers=cls.injected_headers,cookies={settings.SESSION_COOKIE_NAME:cls.session_key}).json()
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

        res = requests.get(cls.get_absolute_url(cls.auth_optional_url),headers=cls.injected_headers).json()
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

        res = requests.get(cls.get_absolute_url(cls.auth_optional_url),headers=cls.injected_headers,cookies={settings.SESSION_COOKIE_NAME:cls.session_key}).json()
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

        res = requests.get(cls.get_absolute_url(cls.auth_basic_url),headers=cls.injected_headers,auth=requests.auth.HTTPBasicAuth(cls.testuser.email, cls.testusertoken.token)).json()
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

