from multiprocessing import Process,Pipe
import time
import random
import json
import requests
from datetime import datetime,timedelta

from django.test import TestCase
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY
from django.contrib.auth import BACKEND_SESSION_KEY,HASH_SESSION_KEY
from django.urls import reverse
from django.utils import timezone
from django.conf import settings

from . import session
from .utils import env,get_usercache
from . import models
from .cache import cache

class PerformanceTestCase(TestCase):
    TEST_USER_NUMBER = env("TEST_USER_NUMBER",default=100)
    TEST_TIME = env("TEST_TIME",default=300) #in seconds
    TEST_INTERVAL = env("TEST_INTERVAL",default=10) / 1000 #configured in milliseconds
    TEST_SERVER = env("TEST_SERVER",default="http://127.0.0.1:8080")
    
    auth_url = "{}{}".format(TEST_SERVER,reverse('auth'))

    min_authtime = 0
    max_authtime = 0
    total_authtime = None
    total_authrequests = 0
    
    format_processtime = staticmethod(lambda t:"{} ms".format(round((t.total_seconds() if hasattr(t,"total_seconds") else t) * 1000,2)))
    
    @classmethod
    def setUpClass(cls):
        models.UserGroup.objects.all().exclude(users=["*"],excluded_users__isnull=True).delete()
        models.UserAuthorization.objects.all().delete()

        cache.refresh_authorization_cache(True)
        if not models.UserGroup.objects.filter(users=["*"], excluded_users__isnull=True).exists():
            public_group = models.UserGroup(name="Public User",groupid="PUBLIC",users=["*"])
            public_group.clean()
            public_group.save()
        if not models.CustomizableUserflow.objects.filter(domain="*").exists():
            default_flow = models.CustomizableUserflow(
                domain='*',
                default='default',
                mfa_set="default_mfa_set",
                mfa_reset="default_mfa_reset",
                email="oim@dbca.wa.gov.au",
                profile_edit="default_profile_edit",
                password_reset="default_password_reset",
                verifyemail_from="oim@dbca.wa.gov.au",
                verifyemail_subject="test"
            )
            default_flow.clean()
            default_flow.save()

        cache.clean_auth_cache(True)
        cache.refresh_authorization_cache(True)

        cls.usercache =get_usercache()

        print("Prepare {} test users".format(cls.TEST_USER_NUMBER))

        testemails = [ "testuser_{:0>4}@dbca.wa.gov.au".format(i) for i in range(1,cls.TEST_USER_NUMBER + 1)]
        cls.testusers = []
    
        for testemail in testemails:
            testuser = models.User.objects.filter(email=testemail).first()
            if not testuser:
                testuser = models.User(username=testemail,email=testemail,first_name="",last_name="",systemuser=True,is_staff=True,is_superuser=False)
                testuser.save()

            cls.usercache.set(settings.GET_USER_KEY(testuser.id),testuser)
            usersession = session.SessionStore()

            usersession[USER_SESSION_KEY] = str(testuser.id)
            usersession[BACKEND_SESSION_KEY] = "django.contrib.auth.backends.ModelBackend"
            usersession[HASH_SESSION_KEY] = ""
            usersession.save()

            #print("create the session({1}) for user({0})".format(testuser,usersession.session_key))

            testuser.session = usersession
            cls.testusers.append(testuser)

    @classmethod
    def tearDownClass(cls):
        for testuser in cls.testusers:
            testuser.session.delete()
            #print("Delete session key {}".format(testuser.session.cache_key_prefix + testuser.session.session_key))
            cls.usercache.delete(settings.GET_USER_KEY(testuser.id))
            #print("Delete user {} from cache with key({})".format(testuser.email,settings.GET_USER_KEY(testuser.id)))


    def run_test(self,c_conn,index,start_time,end_time):
        try:
            cls = self.__class__
            sleep_time = (start_time - timezone.now()).total_seconds()
            if sleep_time and sleep_time > 0:
                time.sleep(sleep_time)
            testuser = cls.testusers[index]
    
            while timezone.now() < end_time :
                start = timezone.now()
                #print("Begin to access url({1}) with session({2}) for user({0})".format(testuser.email,cls.auth_url,testuser.session.session_key))
                res = requests.get(cls.auth_url,cookies={settings.SESSION_COOKIE_NAME:testuser.session.session_key})
                self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
                self.assertTrue(cls.usercache.get(settings.GET_USER_KEY(testuser.id)),msg="User({}<{}> should be cached)".format(testuser.email,testuser.id))
                processtime = timezone.now() - start
                #print("Spend {3} to access url({1}) with session({2}) for user({0})".format(testuser.email,cls.auth_url,testuser.session.session_key,self.format_processtime(processtime)))
                if not cls.min_authtime or cls.min_authtime >  processtime:
                    cls.min_authtime = processtime
        
                if not cls.max_authtime or  cls.max_authtime <  processtime:
                    cls.max_authtime = processtime
        
                cls.total_authrequests += 1
                if not cls.total_authtime:
                    cls.total_authtime = processtime
                else:
                    cls.total_authtime += processtime
                time.sleep(cls.TEST_INTERVAL)
    
            result = {
                "min_authtime"      : self.min_authtime,
                "max_authtime"      : self.max_authtime,
                "total_authrequests": self.total_authrequests,
                "total_authtime"    : self.total_authtime
    
            }
            c_conn.send(result)
            c_conn.close()
        except Exception as ex:
            c_conn.send(ex)
            c_conn.close()


    def test_performance(self):
        cls = self.__class__
        processes = []
        now = timezone.localtime()
        if self.TEST_USER_NUMBER == 1:
            start_time = now
        else:
            start_time = now + timedelta(seconds = 10)
        end_time = start_time + timedelta(seconds = self.TEST_TIME)
        print("Performance test will run from {} to {}".format(start_time.strftime("%Y-%m-%d %H:%M:%S"),end_time.strftime("%Y-%m-%d %H:%M:%S")))
        for i in range(self.TEST_USER_NUMBER):
            p_conn, c_conn = Pipe()
            processes.append((cls.testusers[i],p_conn,Process(target=self.run_test,args=(c_conn,i,start_time,end_time))))

        for testuser,p_conn,p in processes:
            p.start()

        first = True
        for testuser,p_conn,p in processes:
            result = p_conn.recv()
            p.join()
            if isinstance(result,Exception):
                raise result
            if first:
                first = False
                print("Performance testing result:")
            print("    {:<30}:min_authtime : {:<11} , max_authtime : {:<11} , total_authrequests : {:<10} , avg_authtime  : {:<11}".format(
                testuser.email,
                self.format_processtime(result["min_authtime"]),
                self.format_processtime(result["max_authtime"]),
                result["total_authrequests"],
                self.format_processtime(result["total_authtime"].total_seconds() / result["total_authrequests"]) if result["total_authtime"] else 0,
            ))

            if result["min_authtime"]:
                if not cls.min_authtime or cls.min_authtime >  result["min_authtime"]:
                    cls.min_authtime = result["min_authtime"]
        
                if not cls.max_authtime or cls.max_authtime <  result["max_authtime"]:
                    cls.max_authtime = result["max_authtime"]
        
                cls.total_authrequests += result["total_authrequests"]
                if not cls.total_authtime:
                    cls.total_authtime = result["total_authtime"]
                else:
                    cls.total_authtime += result["total_authtime"]
        

        print("    ================================================================================================")
        print("    {:<30}:min_authtime : {:<11} , max_authtime : {:<11} , total_authrequests : {:<10} , avg_authtime  : {:<11}".format(
            "Total",
            self.format_processtime(self.min_authtime),
            self.format_processtime(self.max_authtime),
            self.total_authrequests,
            self.format_processtime(self.total_authtime.total_seconds() / self.total_authrequests) if self.total_authtime else 0,
        ))

        
        
        
        
            

