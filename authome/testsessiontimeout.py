import requests
import time
from datetime import timedelta

from django.conf import settings
from django.test import TestCase
from django.utils import timezone

from . import utils
from . import testutils

from .basetest import BaseTestCase
from . import models
"""
To run this test case, you should have the following resources
1. a shell script to start auth2 server './start_auth2'
2. the set of env files to start different type of auth2 server
  A. .env.auth01.rediscluster: a  auth2 cluster server using redis cluster
  B. .env.auth01.redis: a  auth2 cluster server using redis
3. set the user group
  A. staff group with no timeout setting
  B. public group with timeout setting
"""
class UserSessionTimeoutTestCase(testutils.StartServerMixin,BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super(UserSessionTimeoutTestCase,cls).setUpClass()
        cls.disable_messages()

    def _test(self,auth2_env):
        try:
            sessionage = 36000
            self.start_auth2_server("auth01",18060,auth2_env={"SESSION_AGE":sessionage},start=True)
            for user in ["test1@dbca.wa.gov.au","test@test11.com"]:
                usergroups = models.UserGroup.find_groups(user)[0]
                timeout = models.UserGroup.get_session_timeout(usergroups) or 0
                print("=============================user={} , timeout = {}====================".format(user,timeout))
                before_login = timezone.localtime()
                res = requests.get(self.get_login_user_url(user,servername="auth01"),headers=self.cluster_headers,verify=settings.SSL_VERIFY)
                after_login = timezone.localtime()
                res.raise_for_status()
                session_cookie = self.clean_cookie(res.cookies[settings.SESSION_COOKIE_NAME])
                time.sleep(5)
                sessiondata,ttl1 = self.get_session_data(session_cookie,"auth01",exist=True)
                if timeout:
                    minttl = int((before_login  + timedelta(seconds=timeout)- timezone.localtime()).total_seconds())
                else:
                    minttl = int((before_login  + timedelta(seconds=sessionage)- timezone.localtime()).total_seconds())
                self.assertTrue(ttl1 >= minttl,"The ttl({1}) of the user({0}) should be greater than {2}".format(user,ttl1,minttl))

                time.sleep(5)
                before_profile = timezone.localtime()
                res = requests.get(self.get_profile_url(servername="auth01"),headers=self.cluster_headers,cookies={settings.SESSION_COOKIE_NAME:session_cookie},verify=settings.SSL_VERIFY)
                after_profile = timezone.localtime()

                sessiondata,ttl2 = self.get_session_data(session_cookie,"auth01",exist=True)
                if timeout:
                    minttl = int((before_profile  + timedelta(seconds=timeout)- timezone.localtime()).total_seconds())
                    self.assertTrue(ttl2 > ttl1,"The second ttl({2}) of the user({0}) should be less than the first ttl {1}".format(user,ttl1,ttl2))
                else:
                    minttl = int((before_login  + timedelta(seconds=sessionage)- timezone.localtime()).total_seconds())
                    self.assertTrue(ttl2 < ttl1,"The second ttl({2}) of the user({0}) should be less than the first ttl {1}".format(user,ttl1,ttl2))
                self.assertTrue(ttl2 >= minttl,"The ttl({1}) of the user({0}) should be greater than {2}".format(user,ttl2,minttl))


        finally:
            self.shutdown_all_auth2_servers()

    def test_rediscluster(self):
        print("==========test sessiontimeout with rediscluster============")
        self._test("auth01.rediscluster")

    def test_redis(self):
        print("==========test sessiontimeout with redis============")
        self._test("auth01.redis")
