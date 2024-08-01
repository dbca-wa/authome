from multiprocessing import Process,Pipe
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

from . import utils
from . import models
from authome import performance
from . import testutils
from .serializers import JSONFormater


class MonitoringTestCase(testutils.StartServerMixin,TestCase):
    headers = {}
    cluster_headers = {}

    TEST_USER_NUMBER = utils.env("TEST_USER_NUMBER",default=20)
    TEST_USER_BASEID = int(utils.env("TEST_USER_BASEID",default=1))
    TEST_USER_DOMAIN = utils.env("TEST_USER_DOMAIN",default="dbca.wa.gov.au")
    TEST_TIME = utils.env("TEST_TIME",default=100) #in seconds
    TEST_REQUESTS = utils.env("TEST_REQUESTS",default=0) 
    POST_REQUESTS = utils.env("POST_REQUESTS",default=160) or 160
    REQUEST_INTERVAL = utils.env("REQUEST_INTERVAL",default=500) / 1000 #configured in milliseconds
    TESTED_SERVER = utils.env("TESTED_SERVER",default="https://auth2-dev.dbca.wa.gov.au")
    TRAFFIC_MONITOR_INTERVAL = timedelta(seconds=utils.env("TEST_TRAFFIC_MONITOR_INTERVAL",default=60))
    TEST_DOMAINS = [s.strip() for s in utils.env("TEST_DOMAINS","auth2-dev.dbca.wa.gov.au,whoami-dev.dbca.wa.gov.au").split(",") if s.strip()]

    TESTING_SERVER = utils.env("TESTING_SERVER" ,default=socket.gethostname())

    server_index = 0

    tested_requests={}

    @classmethod
    def get_next_monitor_time(cls,base=None):
        if not base:
            base = timezone.localtime()
        day = datetime(base.year,base.month,base.day,tzinfo=base.tzinfo)
        seconds_in_day = (base - day).seconds
        return day + timedelta(seconds =  seconds_in_day - seconds_in_day % cls.TRAFFIC_MONITOR_INTERVAL.seconds) + cls.TRAFFIC_MONITOR_INTERVAL

    @classmethod
    def get_test_url(cls,test_domain):
        return "https://{}{}".format(test_domain,random.choice(["/sso/auth","/sso/auth_optional","/sso/auth_basic","/sso/auth_basic_optional"]))
        #return "https://{}{}".format(test_domain,random.choice(["/sso/auth_basic_optional"]))

    @classmethod
    def get_test_domain(cls):
        if len(cls.TEST_DOMAINS) == 1:
            return cls.TEST_DOMAINS[0]
        else:
            return random.choice(cls.TEST_DOMAINS)

    @classmethod
    def setUpClass(cls):
        super(MonitoringTestCase,cls).setUpClass()
        cls.disable_messages()

        print("Prepare {} test users".format(cls.TEST_USER_NUMBER))
        testemails = [ "testuser_{:0>4}@{}".format(i,cls.TEST_USER_DOMAIN) for i in range(cls.TEST_USER_BASEID,cls.TEST_USER_BASEID + cls.TEST_USER_NUMBER)]

        cls.testusers = []
        cls.postuserindexes = {}
        for testemail in testemails:
            res = requests.get(cls.get_login_user_url(testemail),headers=cls.headers,verify=settings.SSL_VERIFY)
            res.raise_for_status()
            userprofile = res.json()

            testuser = models.User(email=testemail)
            testuser.token = models.UserToken(user=testuser,enabled=False if "access_token_error" in userprofile else True,token=userprofile["access_token"])
            testuser.session_key = res.cookies[settings.SESSION_COOKIE_NAME]
            cls.testusers.append(testuser)

            if "|" in testuser.session_key:
                clusterid = testuser.session_key.split("|")[1]
                if clusterid not in cls.postuserindexes:
                    cls.postuserindexes[clusterid] = len(cls.testusers) - 1
                testuser.clusterid = clusterid
            elif "default" not in cls.postuserindexes:
                cls.postuserindexes["default"] = len(cls.testusers) - 1
                testuser.clusterid = "default"
            else:
                testuser.clusterid = "default"

        cls.postuserindexes = [v for v in cls.postuserindexes.values()]

    @classmethod
    def tearDownClass(cls):
        super(MonitoringTestCase,cls).tearDownClass()
        print("logout all test user sessions")
        for testuser in cls.testusers:
            res = requests.get(cls.get_logout_url(),headers=cls.headers,cookies={settings.SESSION_COOKIE_NAME:testuser.session_key},allow_redirects=False,verify=settings.SSL_VERIFY)
            res.raise_for_status()
            pass

    def run_test(self,c_conn,index,test_starttime,test_endtime,test_requests):
        try:
            cls = self.__class__
            testuser = cls.testusers[index]
            sleep_time = int((test_starttime - timezone.localtime()).total_seconds()) + 1
            if sleep_time and sleep_time > 0:
                print("{0}: Wait {2} seconds to test the auth2 cluster '{4}' with user '{3}', expected start time '{1}'.".format(utils.format_datetime(timezone.localtime()),utils.format_datetime(test_starttime),sleep_time,testuser,testuser.clusterid))
                time.sleep(sleep_time)
            total_requests = 0
            print("{0}: Begin to test the auth2 cluster '{3}' with user '{2}',expected start time '{1}'".format(utils.format_datetime(timezone.localtime()),utils.format_datetime(test_starttime),testuser,testuser.clusterid))
            while (not test_requests and timezone.localtime() < test_endtime) or (test_requests and total_requests < test_requests) :
                total_requests += 1
                #print("Begin to access url({1}) with session({2}) for user({0})".format(testuser.email,cls.get_auth_url(),testuser.session.session_key))
                test_domain = cls.get_test_domain()
                cls.tested_requests[test_domain] = cls.tested_requests.get(test_domain,0) + 1
                cls.tested_requests["requests"] = cls.tested_requests.get("requests",0) + 1

                res = requests.get(cls.get_test_url(test_domain),cookies={settings.SESSION_COOKIE_NAME:testuser.session_key},verify=settings.SSL_VERIFY)
                res.raise_for_status()

                time.sleep(cls.REQUEST_INTERVAL)
    
            if c_conn:
                c_conn.send(cls.tested_requests)
                c_conn.close()
        except Exception as ex:
            traceback.print_exc()
            if c_conn:
                c_conn.send(ex)
                c_conn.close()
            else:
                raise

    def merge_result(self,result):
        cls = self.__class__
        for k,v in result.items():
            cls.tested_requests[k] = cls.tested_requests.get(k,0) + v

    def merge_trafficdata(self,traffic_data):
        result = {"domains":{}}
        dresult = result["domains"]
        
        for data in traffic_data:
            result["requests"] = result.get("requests",0) + data["requests"]
            result["total_time"] = result.get("total_time",0) + data["total_time"]
            if "min_time"  not in result or result["min_time"] > data["min_time"]:
                result["min_time"] = data["min_time"]
            if "max_time"  not in result or result["max_time"] < data["max_time"]:
                result["max_time"] = data["max_time"]
            result["avg_time"] = result["total_time"] / result["requests"] if result["requests"] else 0
            for k,v in (data["domains"] or {}).items():
                if k not in dresult:
                    dresult[k] = {}
                if isinstance(v,dict):
                    dresult[k]["requests"] = dresult[k].get("requests",0) + v["requests"]
                    dresult[k]["total_time"] = dresult[k].get("total_time",0) + v["total_time"]
                    if "min_time"  not in dresult[k] or dresult[k]["min_time"] > v["min_time"]:
                        dresult[k]["min_time"] = v["min_time"]
                    if "max_time"  not in dresult[k] or dresult[k]["max_time"] < v["max_time"]:
                        dresult[k]["max_time"] = v["max_time"]
                    dresult[k]["avg_time"] = dresult[k]["total_time"] / dresult[k]["requests"] if dresult[k]["requests"] else 0
                else:
                    dresult[k]["requests"] = dresult[k].get("requests",0) + v
        return result

    def test_monitoring(self):
        cls = self.__class__

        processes = []
        test_starttime = self.get_next_monitor_time()
        test_endtime = test_starttime + timedelta(seconds = self.TEST_TIME)

        if cls.TEST_REQUESTS:
            print("Monitoring test will launch {} requests".format(cls.TEST_REQUESTS))
            print("""Test Environment
    Tested Server       : {}
    Testing Server      : {}
    Test User Number    : {}
    Request Interval    : {} milliseconds
    Test Request        : {} 
    Post Requests       : {} """.format(
                cls.TESTED_SERVER,
                cls.TESTING_SERVER,
                cls.TEST_USER_NUMBER,
                cls.REQUEST_INTERVAL * 1000, 
                cls.TEST_REQUESTS,
                cls.POST_REQUESTS
            ))
        else:
            print("Monitoring test will run from {} to {}".format(test_starttime.strftime("%Y-%m-%d %H:%M:%S"),test_endtime.strftime("%Y-%m-%d %H:%M:%S")))
            print("""Test Environment
    Tested Server       : {}
    Testing Server      : {}
    Test User Number    : {}
    Request Interval    : {} milliseconds
    Test Time           : {} seconds
    Post Requests       : {}""".format(
                cls.TESTED_SERVER,
                cls.TESTING_SERVER,
                cls.TEST_USER_NUMBER,
                cls.REQUEST_INTERVAL * 1000, 
                cls.TEST_TIME,
                cls.POST_REQUESTS
            ))

        #send requests to flush the traffic data to redis
        print("Begin to sent {} requests to auth2 to flush the existing traffic data to redis".format(cls.POST_REQUESTS))
        for i in range(50):
            self.flush_traffic_data(cls.testusers[0])

        print("Begin to sent {} requests to auth2 to save the existing traffic data from redis to db".format(cls.POST_REQUESTS))
        trafficdata = self.save_traffic_data(cls.testusers[0])
        merged_trafficdata = self.merge_trafficdata(trafficdata)
        print("The data was saved to db.{}".format(merged_trafficdata))

        if self.TEST_USER_NUMBER == 1:
            self.run_test(None,0,test_starttime,test_endtime,cls.TEST_REQUESTS)
        else:
            for i in range(self.TEST_USER_NUMBER):
                p_conn, c_conn = Pipe()
                processes.append((cls.testusers[i],p_conn,Process(target=self.run_test,args=(c_conn,i,test_starttime,test_endtime,cls.TEST_REQUESTS))))
    
            for testuser,p_conn,p in processes:
                p.start()
    
            exs = []
            for testuser,p_conn,p in processes:
                result = p_conn.recv()
                p.join()
                if isinstance(result,Exception):
                    exs.append((testuser,result))
                    continue
                self.merge_result(result)

            if exs:
                raise Exception("\n".join("{}:{}".format(u,e) for u,e in exs))

        test_endtime = timezone.localtime()

        #send requests to flush the traffic data to redis
        print("Begin to sent {} requests to auth2 to flush the traffic data to redis".format(cls.POST_REQUESTS))
        for i in range(50):
            self.flush_traffic_data(cls.testusers[0])

        #save and return the traffic data
        print("Sent requests to auth2 to save the traffic data from redis to database")
        trafficdata = self.save_traffic_data(cls.testusers[0])
        print("Get the traffic data from auth2")
        print("\n".join(json.dumps(d,cls=JSONFormater) for d in trafficdata))
        merged_trafficdata = self.merge_trafficdata(trafficdata)

        #compare the results
        msgs = []
        for k,v in cls.tested_requests.items():
            if k == "requests":
                if v != merged_trafficdata.get("requests",0):
                    msgs.append("{} - {}: Send {} requests, but auth2 only recorded {} requests".format(utils.format_datetime(test_starttime),utils.format_datetime(test_endtime),v,merged_trafficdata.get("requests",0)))
                else:
                    print("{} - {}: Send {} requests, auth2 recorded {} requests".format(utils.format_datetime(test_starttime),utils.format_datetime(test_endtime),v,merged_trafficdata.get("requests",0)))

            else:
                if v != merged_trafficdata.get("domains",{}).get(k,{}).get("requests",0):
                    msgs.append("{0} - {1}: Send {3} requests to domain '{2}', but auth2 only recorded {4} requests".format(utils.format_datetime(test_starttime),utils.format_datetime(test_endtime),k,v,merged_trafficdata.get("domains",{}).get(k,{}).get("requests",0)))
                else:
                    print("{0} - {1}: Send {3} requests to domain '{2}', auth2 recorded {4} requests".format(utils.format_datetime(test_starttime),utils.format_datetime(test_endtime),k,v,merged_trafficdata["domains"][k]["requests"]))

        if msgs:
            print("Test Failed.\n\t{}".format("\n\t".join(msgs)))
            raise Exception("Test Failed.\n\t{}".format("\n\t".join(msgs)))


        print("Test passed, starttime={} , endtime={} \n\ttested requests {}\n\ttraffic data={}".format(utils.format_datetime(test_starttime),utils.format_datetime(test_endtime),cls.tested_requests,merged_trafficdata))
        
    def _post_teardown(self):
        pass

