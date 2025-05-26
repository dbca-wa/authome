import math
import traceback
import json
from multiprocessing import Process,Pipe
import time
import random
import socket
import requests
from datetime import timedelta,datetime
from urllib.parse import quote_plus

from django.test import TestCase
from django.conf import settings
from django.utils import timezone

from .utils import env
from . import models
from . import utils
from authome.views.tcontrolviews import _check_tcontrol as check_tcontrol

from .basetest import BaseTestCase
from . import testutils

if  settings.TRAFFICCONTROL_ENABLED:
    class TrafficControlPerformanceTestCase(testutils.StartServerMixin,TestCase):
        TEST_SESSION_COOKIE_NAME = env("TEST_SESSION_COOKIE_NAME",default=settings.SESSION_COOKIE_NAME)
        TEST_USER_NUMBER = env("TEST_USER_NUMBER",default=100)
        TEST_USER_BASEID = int(env("TEST_USER_BASEID",default=1))
        TEST_USER_DOMAIN = env("TEST_USER_DOMAIN",default="dbca.wa.gov.au")
        TEST_TIME = int(env("TEST_TIME",default=300)) * 1000 #in seconds, convert it into milliseconds
        TEST_REQUESTS = env("TEST_REQUESTS",default=0) 
        REQUEST_INTERVAL = env("REQUEST_INTERVAL",default="100") #configured in milliseconds
        if "," in REQUEST_INTERVAL:
            REQUEST_INTERVAL = [int(d.strip()) for d in REQUEST_INTERVAL.split(",") if d.strip()]
        else:
            REQUEST_INTERVAL = int(REQUEST_INTERVAL)
        TCONTROLREQUEST_INTERVAL = env("TCONTROLREQUEST_INTERVAL",default="200")  #configured in millisecond s
        if "," in TCONTROLREQUEST_INTERVAL:
            TCONTROLREQUEST_INTERVAL = [int(d.strip()) for d in TCONTROLREQUEST_INTERVAL.split(",") if d.strip()]
        else:
            TCONTROLREQUEST_INTERVAL = int(TCONTROLREQUEST_INTERVAL)
        TESTED_SERVER = env("TESTED_SERVER",default="https://auth2-uat.dbca.wa.gov.au")
        UNITEST_AUTH = (env("TEST_USER",default=None),env("TEST_PASSWORD",default=None))
    
        TESTING_SERVER = env("TESTING_SERVER" ,default=socket.gethostname())
    
        @classmethod
        def setUpClass(cls):
            super().setUpClass()
            url_data = utils.parse_url(cls.TESTED_SERVER)
            if url_data["domain"] in ("auth2.dbca.wa.gov.au","auth2-uat.dbca.wa.gov.au","auth2-dev.dbca.wa.gov.au"):
                cls.request_headers = {"X-LB-HASH-KEY":"dummykey"}
                cls.request_domain = url_data["domain"]
            else:
                cls.request_headers = cls.cluster_headers
                cls.request_domain = cls.request_headers["HOST"]
            
            cls.disable_messages()
    
            print("Prepare {} test users".format(cls.TEST_USER_NUMBER))
            testemails = [ "testuser_{:0>4}@{}".format(i,cls.TEST_USER_DOMAIN) for i in range(cls.TEST_USER_BASEID,cls.TEST_USER_BASEID + cls.TEST_USER_NUMBER)]
    
            cls.testusers = []
            for testemail in testemails:
                res = requests.get(cls.get_login_user_url(testemail),headers=cls.request_headers,verify=settings.SSL_VERIFY,auth=cls.UNITEST_AUTH)
                res.raise_for_status()
                userprofile = res.json()
    
                testuser = models.User(email=testemail)
                testuser.token = models.UserToken(user=testuser,enabled=False if "access_token_error" in userprofile else True,token=userprofile["access_token"])
                testuser.session_key = res.cookies[cls.TEST_SESSION_COOKIE_NAME]
                d = random.randint(0,int(cls.TEST_USER_NUMBER / 2))
                testuser.ip = "10.11.1{}.{}".format(int(d/200), d % 200)
                cls.testusers.append([testuser,None,None,None,None])
    
        @classmethod
        def tearDownClass(cls):
            super().tearDownClass()
            print("logout all test user sessions")
            for testuser in cls.testusers:
                res = requests.get(cls.get_logout_url(),headers=cls.request_headers,cookies={cls.TEST_SESSION_COOKIE_NAME:testuser[0].session_key},allow_redirects=False,verify=settings.SSL_VERIFY)
                res.raise_for_status()
                pass
    
        def performance_test(self,block):
    
            userlimit=20
            userlimitperiod=10
    
            iplimit=0
            iplimitperiod=5
    
            est_processtime = 800
            buckettime = 40
            concurrency=10
            timeout=60
    
            if self.TCONTROLREQUEST_INTERVAL:
                tcontrol_data = {
                    "filter":{
                        "name":"performanceunitest_tcontrol"
                    },
                    "defaults": {
                        "userlimit":userlimit,
                        "userlimitperiod":userlimitperiod,
                        "iplimit":iplimit,
                        "iplimitperiod":iplimitperiod,
                        "est_processtime":est_processtime,
                        "buckettime":buckettime,
                        "concurrency":concurrency,
                        "block":block,
                        "timeout":timeout,
                        "enabled":True
                    }
                }
                print("Configure the traffic control")
                res = requests.post(self.get_update_model_url("TrafficControl"),headers=self.request_headers,verify=settings.SSL_VERIFY,data={"data":json.dumps(tcontrol_data)},auth=self.UNITEST_AUTH)
                res.raise_for_status()
                tcontrol = res.json()
    
                print("Configure the traffic control location")
                location_changed = False
                for loc in ["/test/sso/auth_tcontrol","/test/sso/auth_optional_tcontrol","/test/sso/auth_basic_tcontrol","/test/sso/auth_basic_optional_tcontrol"]:
                    tcontrollocation_data = {
                        "filter":{
                            "domain":self.request_domain,
                            "method":models.TrafficControlLocation.METHODS.get("GET"),
                            "location":loc
                        },
                        "defaults": {
                            "tcontrol_id":tcontrol["id"]
                        }
                    }
                    res = requests.post(self.get_update_model_url("TrafficControlLocation"),headers=self.request_headers,verify=settings.SSL_VERIFY,data={"data":json.dumps(tcontrollocation_data)},auth=self.UNITEST_AUTH)
                    res.raise_for_status()
                    tcontrollocation = res.json()
                    if tcontrollocation["_changed"]:
                        location_changed = True
    
                if tcontrol["_changed"] or location_changed:
                    print("Wait the traffic control data to be refreshed.")
                    res = requests.get(self.get_refresh_modelcache_url("TrafficControl"),headers=self.request_headers,verify=settings.SSL_VERIFY,auth=self.UNITEST_AUTH)
                    res.raise_for_status()
    
                #print("Try to delete tcontrol data")
                #res = requests.get(cls.get_clear_tcontroldata_url(),headers=cls.request_headers,allow_redirects=False,verify=settings.SSL_VERIFY,auth=self.UNITEST_AUTH)
                #res.raise_for_status()
    
            processes = []
            authprocesses = []
            now = timezone.localtime()
            today = now.replace(hour=0,minute=0,second=0,microsecond=0)
            milliseconds = int((now - today).total_seconds() * 1000)
        
            teststarttime = today + timedelta(milliseconds = milliseconds + 2 * est_processtime - milliseconds % est_processtime)
            testendtime = teststarttime + timedelta(milliseconds=self.TEST_TIME + est_processtime - self.TEST_TIME % est_processtime)
                
            print("\n\nBegin to test performance from {0} to {1}".format(
                teststarttime.strftime("%Y-%m-%d %H:%M:%S.%f"),
                testendtime.strftime("%Y-%m-%d %H:%M:%S.%f")
            ))
            if self.TCONTROLREQUEST_INTERVAL:
                for i in range(len(self.testusers)):
                    p_conn, c_conn = Pipe()
                    processes.append((self.testusers[i],p_conn,Process(target=self.run_performancetest_tcontrol,args=(c_conn,tcontrol,teststarttime,testendtime,self.TCONTROLREQUEST_INTERVAL,self.testusers[i][0]))))
        
            if self.REQUEST_INTERVAL:
                for i in range(len(self.testusers)):
                    p_conn, c_conn = Pipe()
                    authprocesses.append((self.testusers[i],p_conn,Process(target=self.run_performancetest_auth,args=(c_conn,teststarttime,testendtime,self.REQUEST_INTERVAL,self.testusers[i][0]))))
        
            for testuser,p_conn,p in processes:
                p.start()
    
            for testuser,p_conn,p in authprocesses:
                p.start()
    
            total_requests = 0
            total_allowed_requests = 0
            total_user_denied_requests = 0
            total_ip_denied_requests = 0
            total_concurrency_denied_requests = 0
            total_failed_requests = 0
            total_tcontrol_disabled_requests = 0
    
            min_exectime = None
            max_exectime = None
            total_exectime = 0
    
            auth_total_requests = 0
            auth_failed_requests = {}
            auth_min_exectime = None
            auth_max_exectime = None
            auth_total_exectime = 0
            
            authmethods_data = {}
    
            for testuser,p_conn,p in processes:
                result = p_conn.recv()#((total_requests,allowed_requests,user_denied_requests,ip_denied_requests,concurrency_denied_requests,failed_requests,tcontrol_disabled_requests),(min_exectime,max_exectime,total_exectime)))
                p.join()
                if isinstance(result,Exception):
                    raise result
                testuser[1] = result[0] #requests,allowd_requests,user_denied_requests,ip_denied_requests,concurrency_denied_requests,failed_requests
                testuser[2] = result[1]
                total_requests += result[0][0]
                total_allowed_requests += result[0][1]
                total_user_denied_requests += result[0][2]
                total_ip_denied_requests += result[0][3]
                total_concurrency_denied_requests += result[0][4]
                total_failed_requests += result[0][5]
                total_tcontrol_disabled_requests += result[0][6]
    
                if min_exectime is None:
                    min_exectime = result[1][0]
                elif min_exectime > result[1][0]:
                    min_exectime = result[1][0]
    
                if max_exectime is None:
                    max_exectime = result[1][1]
                elif max_exectime < result[1][1]:
                    max_exectime = result[1][1]
    
                total_exectime += result[1][2]
    
            for testuser,p_conn,p in authprocesses:
                result = p_conn.recv()#((total_requests,failed_requests,min_exectime,max_exectime,total_exectime),authmethods_data))
                p.join()
                if isinstance(result,Exception):
                    raise result
                testuser[3] = result[0]
                testuser[4] = result[1]
    
                auth_total_requests += result[0][0]
                for k,v in result[0][1].items():
                    auth_failed_requests[k] = auth_failed_requests.get(k,0) + v
    
                if auth_min_exectime is None:
                    auth_min_exectime = result[0][2]
                elif auth_min_exectime > result[0][2]:
                    auth_min_exectime = result[0][2]
    
                if auth_max_exectime is None:
                    auth_max_exectime = result[0][3]
                elif auth_max_exectime > result[0][3]:
                    auth_max_exectime = result[0][3]
    
                auth_total_exectime += result[0][4]
    
                for authmethod,data in result[1].items():
                    d = authmethods_data.get(authmethod)
                    if d is None:
                        d = {}
                        authmethods_data[authmethod] = d
    
                    if d.get("min_exectime") is None:
                        d["min_exectime"] = data["min_exectime"]
                    elif d["min_exectime"] > data["min_exectime"]:
                        d["min_exectime"] = data["min_exectime"]
        
                    if d.get("max_exectime") is None:
                        d["max_exectime"] = data["max_exectime"]
                    elif d["max_exectime"] < data["max_exectime"]:
                        d["max_exectime"] = data["max_exectime"]
    
                    d["total_exectime"] = d.get("total_exectime",0) + data["total_exectime"]
                    d["total_requests"] = d.get("total_requests",0) + data["total_requests"]
    
                    if "failed_requests" not in d:
                        d["failed_requests"] = {}
    
                    for k,v in data.get("failed_requests",{}).items():
                        d["failed_requests"][k] = d["failed_requests"].get(k,0) + v
    
            if self.TCONTROLREQUEST_INTERVAL and self.REQUEST_INTERVAL:
                print("""Performance Test Environment 
        Block Mode: {}
        Total Test Users: {}
        Traffic Control Request Interval: {} milliseconds
        Auth Request Interval: {} milliseconds
        userlimit: {}
        userlimitperiod: {} seconds
        iplimit: {} 
        iplimitperiod: {} seconds
        est_processtime: {} milliseconds
        buckettime: {} milliseconds
        Test Start Time: {}
        Test End Time: {}
        Total Test Time: {} seconds
    
    Traffic Control Performance Test Result Summary
        Total Requests :{}
        Total Allowed Requests: {}
        Total User Denied Requests: {}
        Total IP Denied Requests: {}
        Total Concurrency Denied Requests: {}
        Total Failed Requests: {}
        Total Tcontrol Disabled Requests: {}
        Min Exectime: {} milliseconds
        Max Exectime: {} milliseconds
        Avg Exectime: {} milliseconds
    
    Traffic Control Performance Test Result Details:
        {}
    
    Auth Performance Test Result Summary
        Total Auth Requests: {}
        Failed Auth Requests: {}
        Min Auth Time: {} milliseconds
        Max Auth Time: {} milliseconds
        Avg Auth Time: {} milliseconds
    
        Performance Test Result for each auth method:
            {}
    
    AUth Performance Test Result Details:
        {}
        """.format(
            tcontrol["block"],
            self.TEST_USER_NUMBER,
            self.TCONTROLREQUEST_INTERVAL,
            self.REQUEST_INTERVAL,
            tcontrol["userlimit"],
            tcontrol["userlimitperiod"],
            tcontrol["iplimit"],
            tcontrol["iplimitperiod"],
            tcontrol["est_processtime"],
            tcontrol["buckettime"],
            teststarttime.strftime("%Y-%m-%d %H:%M:%S.%f"),
            testendtime.strftime("%Y-%m-%d %H:%M:%S.%f"),
            (testendtime - teststarttime).total_seconds(),
            
            total_requests,
            total_allowed_requests,
            total_user_denied_requests,
            total_ip_denied_requests,
            total_concurrency_denied_requests,
            total_failed_requests,
            total_tcontrol_disabled_requests,
            min_exectime,
            max_exectime,
            total_exectime / total_requests,
    
            "\n    ".join("""Test Traffic Control User: {} , User IP: {}
            Requests: {} , Allowed: {} , User Denied: {} , IP Denied: {} , Concurrency Denied: {} , Failed: {} , Tcontrol Disabled: {}
            Min Exectime: {} milliseconds , Max Exectime: {} milliseconds , Avg Exectime: {}
    """.format(testuser[0].email,testuser[0].ip,*testuser[1],testuser[2][0],testuser[2][1],testuser[2][2] / testuser[1][0]) for testuser in self.testusers),
    
            auth_total_requests,
            " , ".join("{} Requests: {}".format(k,v) for k,v in auth_failed_requests.items()),
            auth_min_exectime,
            auth_max_exectime,
            auth_total_exectime / auth_total_requests,
            "\n        ".join("{}: Requests:{} , Min Exectime: {} milliseconds ,  Max Exectime: {} milliseconds , Avg Exectime: {} milliseconds{}".format(
                m,
                d["total_requests"],
                d["min_exectime"],
                d["max_exectime"],
                d["total_exectime"] / d["total_requests"],
                " , ".format(" , ".join("{} Requests: {}".format(k,v) for k,v in d["failed_requests"].items())) if d.get("failed_requests") else "" 
            ) for m,d in authmethods_data.items()
            ),
                
            "\n    ".join("""{}: Requests: {} , Min Exectime: {} milliseconds , Max Exectime: {} milliseconds , Avg Exectime: {}{}
            {}""".format(
                    testuser[0].email,
                    testuser[3][0],testuser[3][2],testuser[3][3],testuser[3][4] / testuser[3][0],
                    " , ".format(" , ".join("{} Requests: {}".format(k,v) for k,v in testuser[3][1].items())) if testuser[3][1] else "" ,
                    "\n        ".join("Auth method: {} , Requests:{} , Min Exectime: {} milliseconds ,  Max Exectime: {} milliseconds , Avg Exectime: {} milliseconds{}".format(
                        m,
                        d["total_requests"],
                        d["min_exectime"],
                        d["max_exectime"],
                        d["total_exectime"] / d["total_requests"],
                        " , ".format(" , ".join("{} Requests: {}".format(k,v) for k,v in d["failed_requests"].items())) if d.get("failed_requests") else "" 
                        ) for m,d in testuser[4].items()
                    )
                  ) for testuser in self.testusers)
            ))
    
            elif self.TCONTROLREQUEST_INTERVAL:
                print("""Performance Test Environment 
        Block Mode: {}
        Total Test Users: {}
        Traffic Control Request Interval: {} milliseconds
        userlimit: {}
        userlimitperiod: {} seconds
        iplimit: {} 
        iplimitperiod: {} seconds
        est_processtime: {} milliseconds
        buckettime: {} milliseconds
        Test Start Time: {}
        Test End Time: {}
        Total Test Time: {} seconds
    
    Traffic Control Performance Test Result Summary
        Total Requests :{}
        Total Allowed Requests: {}
        Total User Denied Requests: {}
        Total IP Denied Requests: {}
        Total Concurrency Denied Requests: {}
        Total Failed Requests: {}
        Total Tcontrol Disabled Requests: {}
        Min Exectime: {} milliseconds
        Max Exectime: {} milliseconds
        Avg Exectime: {} milliseconds
    
    Traffic Control Performance Test Result Details:
        {}
        """.format(
            tcontrol["block"],
            self.TEST_USER_NUMBER,
            self.TCONTROLREQUEST_INTERVAL,
            tcontrol["userlimit"],
            tcontrol["userlimitperiod"],
            tcontrol["iplimit"],
            tcontrol["iplimitperiod"],
            tcontrol["est_processtime"],
            tcontrol["buckettime"],
            teststarttime.strftime("%Y-%m-%d %H:%M:%S.%f"),
            testendtime.strftime("%Y-%m-%d %H:%M:%S.%f"),
            (testendtime - teststarttime).total_seconds(),
            
            total_requests,
            total_allowed_requests,
            total_user_denied_requests,
            total_ip_denied_requests,
            total_concurrency_denied_requests,
            total_failed_requests,
            total_tcontrol_disabled_requests,
            min_exectime,
            max_exectime,
            total_exectime / total_requests,
    
            "\n    ".join("""Test Traffic Control User: {} , User IP: {}
            Requests: {} , Allowed: {} , User Denied: {} , IP Denied: {} , Concurrency Denied: {} , Failed: {} , Tcontrol Disabled: {}
            Min Exectime: {} milliseconds , Max Exectime: {} milliseconds , Avg Exectime: {}
    """.format(testuser[0].email,testuser[0].ip,*testuser[1],testuser[2][0],testuser[2][1],testuser[2][2] / testuser[1][0]) for testuser in self.testusers)
            ))
    
            elif self.REQUEST_INTERVAL:
                print("""Performance Test Environment 
        Total Test Users: {}
        Auth Request Interval: {} milliseconds
        Test Start Time: {}
        Test End Time: {}
        Total Test Time: {} seconds
    
    Auth Performance Test Result Summary
        Total Auth Requests: {}
        Failed Auth Requests: {}
        Min Auth Time: {} milliseconds
        Max Auth Time: {} milliseconds
        Avg Auth Time: {} milliseconds
    
        Performance Test Result for each auth method:
            {}
    
    AUth Performance Test Result Details:
        {}
        """.format(
            self.TEST_USER_NUMBER,
            self.REQUEST_INTERVAL,
            teststarttime.strftime("%Y-%m-%d %H:%M:%S.%f"),
            testendtime.strftime("%Y-%m-%d %H:%M:%S.%f"),
            (testendtime - teststarttime).total_seconds(),
            
            auth_total_requests,
            " , ".join("{} Requests: {}".format(k,v) for k,v in auth_failed_requests.items()),
            auth_min_exectime,
            auth_max_exectime,
            auth_total_exectime / auth_total_requests,
    
            "\n        ".join("{}: Requests:{} , Min Exectime: {} milliseconds ,  Max Exectime: {} milliseconds , Avg Exectime: {} milliseconds".format(
                m,
                d["total_requests"],
                d["min_exectime"],
                d["max_exectime"],
                d["total_exectime"] / d["total_requests"],
                " , ".format(" , ".join("{} Requests: {}".format(k,v) for k,v in d["failed_requests"].items())) if d.get("failed_requests") else "" 
            ) for m,d in authmethods_data.items()
            ),
                
            "\n    ".join("""Test Auth User({}): Requests: {} , Min Exectime: {} milliseconds , Max Exectime: {} milliseconds , Avg Exectime: {}{}
            {}""".format(
                    testuser[0].email,
                    testuser[3][0],testuser[3][2],testuser[3][3],testuser[3][4] / testuser[3][0],
                    " , ".format(" , ".join("{} Requests: {}".format(k,v) for k,v in testuser[3][1].items())) if testuser[3][1] else "" ,
                    "\n        ".join("Auth method: {} , Requests:{} , Min Exectime: {} milliseconds ,  Max Exectime: {} milliseconds , Avg Exectime: {} milliseconds{}".format(
                        m,
                        d["total_requests"],
                        d["min_exectime"],
                        d["max_exectime"],
                        d["total_exectime"] / d["total_requests"],
                        " , ".format(" , ".join("{} Requests: {}".format(k,v) for k,v in d["failed_requests"].items())) if d.get("failed_requests") else "" 
                    ) for m,d in testuser[4].items()
                    )
                  ) for testuser in self.testusers)
                ))
    
    
    
        def run_performancetest_tcontrol(self,c_conn,tcontrol,teststarttime,testendtime,request_interval,testuser,exempt=False):
            try:
                total_requests = 0
                allowed_requests = 0
                failed_requests = 0
                user_denied_requests = 0
                ip_denied_requests = 0
                concurrency_denied_requests = 0
                tcontrol_disabled_requests = 0
                min_exectime = None
                max_exectime = None
                total_exectime = 0
        
                now = timezone.localtime()
                waittime = (teststarttime - now).total_seconds()
                if waittime >= 0:
                    print("\n{}({}): wait {} milliseconds to start traffic control performance testing".format(testuser.email,testuser.ip,waittime))
                    time.sleep(waittime)
                else:
                    print("\n{}({}): start traffic control performance testing".format(testuser.email,testuser.ip))
         
                while timezone.localtime() < testendtime:
                    if isinstance(request_interval,int):
                        time.sleep(request_interval / 1000)
                    else:
                        time.sleep(random.randint(*request_interval) / 1000)
                    i = random.randint(1,10)
                    start = timezone.localtime()
                    try:
                        if i <= 4:
                            authmethod = "auth_tcontrol"
                            url=self.get_auth_tcontrol_url()
                            res = requests.get(url,cookies={self.TEST_SESSION_COOKIE_NAME:testuser.session_key},headers=self.request_headers,allow_redirects=False,verify=settings.SSL_VERIFY)
                        elif i <= 6:
                            authmethod = "basicauth_tcontrol"
                            url=self.get_basicauth_tcontrol_url()
                            res = requests.get(url,cookies={self.TEST_SESSION_COOKIE_NAME:testuser.session_key},auth=(testuser.email, testuser.token),headers=self.request_headers,allow_redirects=False,verify=settings.SSL_VERIFY)
                        elif i <= 8:
                            authmethod = "auth_optional_tcontrol"
                            url=self.get_auth_optional_tcontrol_url()
                            res = requests.get(url,cookies={self.TEST_SESSION_COOKIE_NAME:testuser.session_key},headers=self.request_headers,allow_redirects=False,verify=settings.SSL_VERIFY)
                        else:
                            authmethod = "basicauth_optional_tcontrol"
                            url=self.get_basicauth_optional_tcontrol_url()
                            res = requests.get(url,cookies={self.TEST_SESSION_COOKIE_NAME:testuser.session_key},auth=(testuser.email, testuser.token),headers=self.request_headers,allow_redirects=False,verify=settings.SSL_VERIFY)
                        res.raise_for_status()
                        result = res.json()
                    except Exception as ex:
                        traceback.print_exc()
                        result = [True,str(ex),0]
                    print("***Get tcontrol result {1}\t\t\t url='{0}'".format(url,result))
                    if isinstance(result[1],dict):
                        if result[1].get("bookingtime"):
                            endtime = timezone.make_aware(datetime.strptime(result[1].get("bookingtime"),"%Y-%m-%d %H:%M:%S.%f"))
                        else:
                            endtime = timezone.localtime()
                    elif result[1]:
                        try:
                            endtime = timezone.make_aware(datetime.strptime(result[1],"%Y-%m-%d %H:%M:%S.%f"))
                        except:
                            endtime = timezone.localtime()
                    else:
                        endtime = timezone.localtime()
                    exectime = (endtime - start).total_seconds() * 1000
                    total_requests += 1
                    if min_exectime is None:
                        min_exectime = exectime
                    elif min_exectime > exectime:
                        min_exectime = exectime
        
                    if max_exectime is None:
                        max_exectime = exectime
                    elif max_exectime < exectime:
                        max_exectime = exectime
        
                    total_exectime += exectime
    
                    if result[0]:
                        if result[1] and isinstance(result[1],str):
                            if result[1] == "_DISABLED_":
                                tcontrol_disabled_requests += 1
                                continue
                            else:
                                failed_requests += 1
                        else:
                            allowed_requests += 1
                    elif result[1] == "USER":
                        user_denied_requests += 1
                    elif result[1] == "IP":
                        ip_denied_requests += 1
                    else:
                        concurrency_denied_requests += 1
    
                c_conn.send(((total_requests,allowed_requests,user_denied_requests,ip_denied_requests,concurrency_denied_requests,failed_requests,tcontrol_disabled_requests),(min_exectime,max_exectime,total_exectime)))
                c_conn.close()
            except Exception as ex:
                traceback.print_exc()
                c_conn.send(ex)
                c_conn.close()
    
        def run_performancetest_auth(self,c_conn,teststarttime,testendtime,request_interval,testuser):
            try:
                total_requests = 0
                failed_requests = {}
                min_exectime = None
                max_exectime = None
                total_exectime = 0
    
                authmethods_data = {}
    
                now = timezone.localtime()
                waittime = (teststarttime - now).total_seconds()
                if waittime >= 0:
                    print("\n{}: wait {} milliseconds to start auth performance testing".format(testuser.email,waittime))
                    time.sleep(waittime)
                else:
                    print("\n{}: start auth performance testing".format(testuser.email))
         
                while timezone.localtime() < testendtime:
                    if isinstance(request_interval,int):
                        time.sleep(request_interval / 1000)
                    else:
                        time.sleep(random.randint(*request_interval) / 1000)
                    i = random.randint(1,10)
                    start = timezone.localtime()
                    try:
                        if i <= 4:
                            authmethod = "auth"
                            res = requests.get(self.get_auth_url(),cookies={self.TEST_SESSION_COOKIE_NAME:testuser.session_key},headers=self.request_headers,allow_redirects=False,verify=settings.SSL_VERIFY)
                        elif i <= 6:
                            authmethod = "basicauth"
                            res = requests.get(self.get_basicauth_url(),cookies={self.TEST_SESSION_COOKIE_NAME:testuser.session_key},auth=(testuser.email, testuser.token),headers=self.request_headers,allow_redirects=False,verify=settings.SSL_VERIFY)
                        elif i <= 8:
                            authmethod = "auth_optional"
                            res = requests.get(self.get_auth_optional_url(),cookies={self.TEST_SESSION_COOKIE_NAME:testuser.session_key},headers=self.request_headers,allow_redirects=False,verify=settings.SSL_VERIFY)
                        else:
                            authmethod = "basicauth_optional"
                            res = requests.get(self.get_basicauth_optional_url(),cookies={self.TEST_SESSION_COOKIE_NAME:testuser.session_key},auth=(testuser.email, testuser.token),headers=self.request_headers,allow_redirects=False,verify=settings.SSL_VERIFY)
                        res.raise_for_status()
                        failed = None
                    except Exception as ex:
                        traceback.print_exc()
                        failed = ex.__class__.__name__
    
                    exectime = (timezone.localtime() - start).total_seconds() * 1000
    
                    total_requests += 1
                    data = authmethods_data.get(authmethod)
                    if data is None:
                        data = {}
                        authmethods_data[authmethod] = data
    
                    if failed:
                       failed_requests[failed] = failed_requests.get(failed,0) + 1
    
                    if min_exectime is None:
                        min_exectime = exectime
                    elif min_exectime > exectime:
                        min_exectime = exectime
        
                    if max_exectime is None:
                        max_exectime = exectime
                    elif max_exectime < exectime:
                        max_exectime = exectime
    
                    total_exectime += exectime
        
                    data["total_requests"] = data.get("total_requests",0) + 1
                    if "failed_requests" not in data:
                        data["failed_requests"] = {}
                    if failed:
                        data["failed_requests"][failed] = data["failed_requests"].get(failed,0) + 1
    
                    if data.get("min_exectime") is None:
                        data["min_exectime"] = exectime
                    elif data["min_exectime"] > exectime:
                        data["min_exectime"] = exectime
        
                    if data.get("max_exectime") is None:
                        data["max_exectime"] = exectime
                    elif data["max_exectime"] < exectime:
                        data["max_exectime"] = exectime
        
                    data["total_exectime"] = data.get("total_exectime",0) + exectime
    
                c_conn.send(((total_requests,failed_requests,min_exectime,max_exectime,total_exectime),authmethods_data))
                c_conn.close()
            except Exception as ex:
                traceback.print_exc()
                c_conn.send(ex)
                c_conn.close()
    
        def atest_performance(self):
            self.performance_test(False)
    
                        
        def test_blockmode_performance(self):
            self.performance_test(True)
    
