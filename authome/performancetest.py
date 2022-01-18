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

from . import session
from .utils import env,get_usercache
from . import models
from .cache import cache
from authome import performance


class PerformanceTestCase(TestCase):
    TEST_USER_NUMBER = env("TEST_USER_NUMBER",default=100)
    TEST_USER_BASEID = int(env("TEST_USER_BASEID",default=1))
    TEST_TIME = env("TEST_TIME",default=300) #in seconds
    TEST_REQUESTS = env("TEST_REQUESTS",default=0) 
    REQUEST_INTERVAL = env("REQUEST_INTERVAL",default=10) / 1000 #configured in milliseconds
    TESTED_SERVER = env("TESTED_SERVER",default="http://127.0.0.1:8080")
    PRINT_USER_PERFORMANCE_DATA = env("PRINT_USER_PERFORMANCE_DATA",default=False)
    DOWNLOAD_TEST_DATA = env("DOWNLOAD_TEST_DATA",default=False)
    TEST_DATA_FILE = env("TEST_DATA_FILE")
    CLEAN_TEST_CACHE_DATA = False if DOWNLOAD_TEST_DATA else env("CLEAN_TEST_CACHE_DATA",default=(False if TEST_DATA_FILE else True))

    TESTING_SERVER = env("TESTING_SERVER" ,default=socket.gethostname())
    
    auth_url = "{}/sso/authperformance".format(TESTED_SERVER)

    authrequest = {
        "min_processtime" : None,
        "max_processtime" : None,
        "total_processtime" : None,
        "total_requests" : 0,
        "errors": {
        },
        "processes":{
        },
        "steps":[
            [
                "requestsend",
                {
                    "min_processtime": None,
                    "max_processtime": None,
                    "total_processtime": None,
                    "total_requests" : 0
                },
                []
            ],
            [
                "requestprocessing",
                {
                    "min_processtime": None,
                    "max_processtime": None,
                    "total_processtime": None,
                    "total_requests" : 0
                },
                []
            ],
            [
                "responsesend",
                {
                    "min_processtime": None,
                    "max_processtime": None,
                    "total_processtime": None,
                    "total_requests" : 0
                },
                []
            ]
        ]
    }

    min_requestsendtime = 0
    max_requestsendtime = 0
    total_requestsendtime = 0
    
    min_responsesendtime = 0
    max_reponsesendtime = 0
    total_responsesendtime = 0
    
    format_datetime = staticmethod(lambda t: t.strftime("%Y-%m-%d %H:%M:%S.%f") if t  else "N/A")
    format_processtime = staticmethod(lambda t: ("{} ms".format(round((t.total_seconds() if hasattr(t,"total_seconds") else t) * 1000,2))) if t  else "N/A")

    @classmethod
    def setUpClass(cls):
        print("Prepare {} test users".format(cls.TEST_USER_NUMBER))
        testemails = [ "testuser_{:0>4}@dbca.wa.gov.au".format(i) for i in range(cls.TEST_USER_BASEID,cls.TEST_USER_BASEID + cls.TEST_USER_NUMBER)]

        if not cls.DOWNLOAD_TEST_DATA and cls.TEST_DATA_FILE:
            with open(cls.TEST_DATA_FILE,'r') as f:
                testdata = json.loads(f.read())
            
            settings.CACHE_SESSION_SERVER = testdata["CACHE_SESSION_SERVER"]
            settings.CACHE_USER_SERVER = testdata["CACHE_USER_SERVER"]
            settings.CACHE_SERVER = testdata["CACHE_SERVER"]
            settings.SESSION_COOKIE_NAME = testdata.get("SESSION_COOKIE_NAME")
            settings.CACHE_KEY_PREFIX = testdata.get("CACHE_KEY_PREFIX")
            session.SessionStore.cache_key_prefix = "{}_session".format(settings.CACHE_KEY_PREFIX) if settings.CACHE_KEY_PREFIX else "session"
            usersessiondata = testdata["usersession"]

            cls.TESTED_SERVER = testdata["TESTED_SERVER"]
            cls.auth_url = "{}/sso/authperformance".format(cls.TESTED_SERVER)
            cls.CLEAN_TEST_CACHE_DATA = False 
            cls.TEST_TIME = testdata["TEST_TIME"]
            cls.TEST_REQUESTS = testdata["TEST_REQUESTS"]
            cls.REQUEST_INTERVAL = testdata["REQUEST_INTERVAL"] / 1000 

            cls.testusers = []
            for email in testemails:
                userdata = usersessiondata[email]
                testuser = models.User(email=email,id=userdata["id"])

                usersession = session.SessionStore(userdata["sessionkey"])

                testuser.session=usersession
                cls.testusers.append(testuser)
            print("Loaded {1} test users from file({0})".format(cls.TEST_DATA_FILE,cls.TEST_USER_NUMBER))
        else:
            cls.usercache =get_usercache()

            cls.testusers = []
        
            userid = 0
            for testemail in testemails:
                userid -= 1
                testuser = models.User(username=testemail,email=testemail,first_name="",last_name="",systemuser=True,is_staff=True,is_superuser=False,id=userid)
    
                cls.usercache.set(settings.GET_USER_KEY(testuser.id),testuser,86400 * 14)
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
        if cls.CLEAN_TEST_CACHE_DATA:
            print("Clean the cached session data and user data")
            for testuser in cls.testusers:
                testuser.session.delete()
                #print("Delete session key {}".format(testuser.session.cache_key_prefix + testuser.session.session_key))
                cls.usercache.delete(settings.GET_USER_KEY(testuser.id))
                #print("Delete user {} from cache with key({})".format(testuser.email,settings.GET_USER_KEY(testuser.id)))
                pass

    def parse_processingsteps(self,test_starttime,test_endtime,starttime,endtime,processname,processcreatetime,processingsteps):
        cls = self.__class__
        index = [0]
        p_steps = [] #a list of tuple(parent step, last processed sub step index,parent_perforance_data)
        step = processingsteps[0]
        p_performance_dict = None
        p_step_data = None
        def _process_processtime(performance_dict,processtime):
            if not performance_dict["min_processtime"] or performance_dict["min_processtime"] >  processtime:
                performance_dict["min_processtime"] = processtime
    
            if not performance_dict["max_processtime"] or  performance_dict["max_processtime"] <  processtime:
                performance_dict["max_processtime"] = processtime

            if not performance_dict["total_processtime"]:
                performance_dict["total_processtime"] = processtime
            else:
                performance_dict["total_processtime"] += processtime
            performance_dict["total_requests"] += 1

        while step:
            if step == processingsteps[0]:
                #calculate the performance against process
                p_performance_dict = cls.authrequest["processes"].get(processname)
                if not p_performance_dict:
                    p_performance_dict = {
                        "processcreatetime":processcreatetime.strftime("%Y-%m-%d %H:%M:%S.%f"),
                        "createdafter":"0 milliseconds" if processcreatetime <= test_starttime else self.format_processtime(processcreatetime - test_starttime),
                        "min_processtime": None,
                        "max_processtime": None,
                        "total_processtime": None,
                        "total_requests" : 0
                    }
                    cls.authrequest["processes"][processname] = p_performance_dict

                _process_processtime(p_performance_dict,step[2] - step[1])

                #caclulate the overall performance 
                p_performance_dict = cls.authrequest["steps"]
                _process_processtime(p_performance_dict[0][1],step[1] - starttime)

                _process_processtime(p_performance_dict[2][1],endtime - step[2])

                _process_processtime(p_performance_dict[1][1],step[2] - step[1])

                p_performance_dict = p_performance_dict[1]
            else:
                performance_dict = next((o for o in p_performance_dict[2] if o[0] == step[0]), None)
                if not performance_dict:
                    performance_dict = [
                        step[0],
                        {
                            "min_processtime" : None,
                            "max_processtime" : None,
                            "total_processtime" : None,
                            "total_requests" : 0
                        },
                        []
                    ]
                    p_performance_dict[2].append(performance_dict)
                
                processtime = step[2] - step[1]
                _process_processtime(performance_dict[1],processtime)

                if p_step_data[3]:
                    p_step_data[3] += processtime
                else:
                    p_step_data[3] = processtime

                p_performance_dict = performance_dict


            if step[4]:
                p_step_data = [step,p_performance_dict,0,None] #[parent step, parent performance dict, last processed sub step index,monitored process time]
                p_steps.append(p_step_data)
                step = step[4][0]
            else:
                step = None
                while p_steps and not step:
                    p_step_data = p_steps.pop()
                    p_step,p_performance_dict,substep_index,p_monitored_processtime = p_step_data
                    substep_index += 1
                    if substep_index >= len(p_step[4]):
                        #all substeps are processed,
                        #add a others step
                        performance_dict = next((o for o in p_performance_dict[2] if o[0] == "others"), None)
                        if not performance_dict:
                            performance_dict = [
                                "others",
                                {
                                    "min_processtime" : 0,
                                    "max_processtime" : 0,
                                    "total_processtime" : None,
                                    "total_requests" : 0
                                },
                                []
                            ]
                            p_performance_dict[2].append(performance_dict)

                        _process_processtime(performance_dict[1],(p_step[2] - p_step[1]) - p_monitored_processtime)
                        continue

                    step = p_step[4][substep_index]
                    p_step_data[2] = substep_index
                    p_steps.append(p_step_data)


    def run_test(self,c_conn,index,test_starttime,test_endtime):
        try:
            cls = self.__class__
            sleep_time = (test_starttime - timezone.localtime()).total_seconds()
            if sleep_time and sleep_time > 0:
                time.sleep(sleep_time)
            testuser = cls.testusers[index]

            httprequests = 0
            while (not cls.TEST_REQUESTS and timezone.localtime() < test_endtime) or (cls.TEST_REQUESTS and httprequests < cls.TEST_REQUESTS) :
                httprequests += 1
                starttime = timezone.localtime()
                try:
                    #print("Begin to access url({1}) with session({2}) for user({0})".format(testuser.email,cls.auth_url,testuser.session.session_key))
                    res = requests.get(cls.auth_url,cookies={settings.SESSION_COOKIE_NAME:testuser.session.session_key})
                    res = res.json()
                    endtime = timezone.localtime()
                    self.assertEqual(res["status_code"],200,msg="Should return 200 response for authenticated request")
                    processingsteps = performance.parse_processingsteps(res["processingsteps"])
                    processname = res["processname"]
                    processcreatetime = performance.parse_datetime(res["processcreatetime"])
                    self.assertEqual(len(processingsteps),1,msg="Each request should have one and only one steps, but now have {} steps".format(len(processingsteps)))
                    processtime = endtime - starttime
                    if cls.TEST_REQUESTS:
                        self.print_processingsteps(testuser.email,"/sso/auth",starttime,endtime,processname,processingsteps)
    
                    #print("Spend {3} to access url({1}) with session({2}) for user({0})".format(testuser.email,cls.auth_url,testuser.session.session_key,self.format_processtime(processtime)))
                    if not cls.authrequest["min_processtime"] or cls.authrequest["min_processtime"] >  processtime:
                        cls.authrequest["min_processtime"] = processtime
            
                    if not cls.authrequest["max_processtime"] or  cls.authrequest["max_processtime"] <  processtime:
                        cls.authrequest["max_processtime"] = processtime
            
                    cls.authrequest["total_requests"] += 1
                    if not cls.authrequest["total_processtime"]:
                        cls.authrequest["total_processtime"] = processtime
                    else:
                        cls.authrequest["total_processtime"] += processtime
    
                    self.parse_processingsteps(test_starttime,test_endtime,starttime,endtime,processname,processcreatetime,processingsteps)
                except Exception as ex:
                    if cls.TEST_USER_NUMBER <= 2 and cls.TEST_REQUESTS < 5:
                        traceback.print_exc()
                    endtime = timezone.localtime()
                    processtime = endtime - starttime
                    error = str(ex)
                    errordata = cls.authrequest["errors"].get(error)
                    if not errordata:
                        errordata = {
                            "min_processtime" : None,
                            "max_processtime" : None,
                            "total_processtime" : None,
                            "total_requests" : 0
                        }
                        cls.authrequest["errors"][error] = errordata

                    errordata["total_requests"]= errordata.get("total_requests",0) + 1
                    if not errordata["min_processtime"] or errordata["min_processtime"] >  processtime:
                        errordata["min_processtime"] = processtime
            
                    if not errordata["max_processtime"] or  errordata["max_processtime"] <  processtime:
                        errordata["max_processtime"] = processtime
            
                    if not errordata["total_processtime"]:
                        errordata["total_processtime"] = processtime
                    else:
                        errordata["total_processtime"] += processtime

                time.sleep(cls.REQUEST_INTERVAL)
    
            if c_conn:
                c_conn.send(cls.authrequest)
                c_conn.close()
        except Exception as ex:
            if cls.TEST_USER_NUMBER <= 2 and cls.TEST_REQUESTS < 5:
                traceback.print_exc()
            if c_conn:
                c_conn.send(ex)
                c_conn.close()
            else:
                raise


    def merge_performancedata(self,performancedata):
        cls = self.__class__
        def _merge_performancedata(totaldata,userdata):
            processtime = userdata["min_processtime"]
            if not totaldata["min_processtime"] or totaldata["min_processtime"] >  processtime:
                totaldata["min_processtime"] = processtime
    
            processtime = userdata["max_processtime"]
            if not totaldata["max_processtime"] or  totaldata["max_processtime"] <  processtime:
                totaldata["max_processtime"] = processtime
    
            totaldata["total_requests"] += userdata["total_requests"]

            processtime = userdata["total_processtime"]
            if not totaldata["total_processtime"]:
                totaldata["total_processtime"] = processtime
            else:
                totaldata["total_processtime"] += processtime

        for processname,processdata in performancedata["processes"].items():
            m_processdata = cls.authrequest["processes"].get(processname)
            if not m_processdata:
                m_processdata = {
                    "processcreatetime":processdata["processcreatetime"],
                    "createdafter":processdata["createdafter"],
                    "min_processtime" : None,
                    "max_processtime" : None,
                    "total_processtime" : None,
                    "total_requests" : 0
                }
                cls.authrequest["processes"][processname] = m_processdata
         
            _merge_performancedata(m_processdata,processdata)

        if performancedata["errors"]:
            for error,errordata in performancedata["errors"].items():
                m_errordata = cls.authrequest["errors"].get(error)
                if not m_errordata:
                    m_errordata = {
                        "min_processtime" : None,
                        "max_processtime" : None,
                        "total_processtime" : None,
                        "total_requests" : 0
                    }
                    cls.authrequest["errors"][error] = m_errordata
             
                _merge_performancedata(m_errordata,errordata)

        if not performancedata["total_requests"]:
            return

        _merge_performancedata(cls.authrequest,performancedata)

        def _merge_steps_data(stepsdata,userstepsdata):
            for userstepdata in userstepsdata:
                stepdata = next((o for o in stepsdata if o[0] == userstepdata[0]), None)
                if not stepdata:
                    stepdata = [userstepdata[0],dict(userstepdata[1]),[]]
                    stepsdata.append(stepdata)
                else:
                    _merge_performancedata(stepdata[1],userstepdata[1])

                _merge_steps_data(stepdata[2],userstepdata[2])

        _merge_steps_data(cls.authrequest["steps"],performancedata["steps"])

    def print_processingsteps(self,name,requesttype,starttime,endtime,processname,processingsteps):
        processtime = (endtime - starttime).total_seconds()
        print("{:<20} {:<30} - starttime : {} endtime: {} processing time : {:<10} process : {}".format(
            requesttype,
            name,
            self.format_datetime(starttime),
            self.format_datetime(endtime),
            self.format_processtime(processtime),
            processname
        ))
        def _print_steps(indent,total_processtime,steps):
            monitored_processtime = 0
            for step in steps:
                print("{}{:<30} - starttime : {} endtime : {} processing time : {:<10} , Percentage: {}".format(
                    indent,
                    step[0],
                    self.format_datetime(step[1]),
                    self.format_datetime(step[2]),
                    self.format_processtime(step[2] - step[1]),
                    "{}%".format(round(((step[2] - step[1]).total_seconds() / total_processtime) * 100,2))
                ))
                monitored_processtime += (step[2] - step[1]).total_seconds()
                _print_steps(indent + "    ",(step[2] - step[1]).total_seconds(),step[4])
            if steps:
                other_processtime =  total_processtime - monitored_processtime
                if other_processtime > 0:
                    print("{}{:<30} - processing time : {:<10} , Percentage: {}".format(
                        indent,
                        "others",
                        self.format_processtime(other_processtime),
                        "{}%".format(round((other_processtime / total_processtime) * 100,2))
                    ))


        _print_steps("    ",processtime,processingsteps)
        
    def print_performancedata(self,name,performancedata):
        print("{:<30} - Requests : {:<10} , Min Processtime : {:<11} , Max Processtime : {:<11} , Avg Processtime  : {:<11}".format(
            name,
            performancedata["total_requests"],
            self.format_processtime(performancedata["min_processtime"]),
            self.format_processtime(performancedata["max_processtime"]),
            self.format_processtime(performancedata["total_processtime"].total_seconds() / performancedata["total_requests"]) if performancedata["total_processtime"] else 0,
        ))
        def _print_steps(indent,total_processtime,steps):
            for step in steps:
                print("{}{:<30}: Requests : {:<10} , Min Processtime : {:<11} , Max Processtime : {:<11} , Avg Processtime  : {:<11}, Percentage: {}".format(
                    indent,
                    step[0],
                    step[1]["total_requests"],
                    self.format_processtime(step[1]["min_processtime"]),
                    self.format_processtime(step[1]["max_processtime"]),
                    self.format_processtime(step[1]["total_processtime"].total_seconds() / step[1]["total_requests"]) if step[1]["total_processtime"] else 0,
                    "{}%".format(round((step[1]["total_processtime"].total_seconds() / total_processtime) * 100,2)) if total_processtime else "N/A"
                ))
                _print_steps(indent + "    ",step[1]["total_processtime"].total_seconds() if step[1]["total_processtime"] else None,step[2])

        _print_steps("    ",performancedata["total_processtime"].total_seconds() if performancedata["total_processtime"] else None,performancedata["steps"])
        
        print("    ------------------------------------------------------------------------------------")
        print("    Processes")
        for processname,processdata in performancedata["processes"].items():
            print("        {:<50} Created After: {:<30} - Requests : {:<10} , Min Processtime : {:<11} , Max Processtime : {:<11} , Avg Processtime  : {:<11}".format(
                processname,
                processdata["createdafter"],
                processdata["total_requests"],
                self.format_processtime(processdata["min_processtime"]),
                self.format_processtime(processdata["max_processtime"]),
                self.format_processtime(processdata["total_processtime"].total_seconds() / processdata["total_requests"]) if processdata["total_processtime"] else 0,
            ))

        if performancedata["errors"]:
            print("    ------------------------------------------------------------------------------------")
            print("    Errors")
            for error,errordata in performancedata["errors"].items():
                print("        {:<30} - Requests : {:<10} , Min Processtime : {:<11} , Max Processtime : {:<11} , Avg Processtime  : {:<11}".format(
                    error,
                    errordata["total_requests"],
                    self.format_processtime(errordata["min_processtime"]),
                    self.format_processtime(errordata["max_processtime"]),
                    self.format_processtime(errordata["total_processtime"].total_seconds() / errordata["total_requests"]) if errordata["total_processtime"] else 0,
                ))

    def test_performance(self):
        cls = self.__class__

        if cls.DOWNLOAD_TEST_DATA:
            usersessiondata = dict([(u.email,{"id":u.id,"sessionkey":u.session.session_key}) for u in cls.testusers])
            testdata = {
                "TESTED_SERVER" : cls.TESTED_SERVER,
                "TEST_TIME" : cls.TEST_TIME,
                "TEST_REQUESTS" : cls.TEST_REQUESTS,
                "REQUEST_INTERVAL" : cls.REQUEST_INTERVAL * 1000 ,
                "CACHE_SESSION_SERVER" : settings.CACHE_SESSION_SERVER,
                "CACHE_USER_SERVER" : settings.CACHE_USER_SERVER,
                "CACHE_SERVER" : settings.CACHE_SERVER,
                "CACHE_KEY_PREFIX":settings.CACHE_KEY_PREFIX,
                "SESSION_COOKIE_NAME":settings.SESSION_COOKIE_NAME,
                "usersession" : usersessiondata
            }
            with open(cls.TEST_DATA_FILE,'w') as f:
                f.write(json.dumps(testdata,indent=4))
            print("Test data was exported to file '{}'".format(cls.TEST_DATA_FILE))
            return
        elif cls.TEST_DATA_FILE and cls.CLEAN_TEST_CACHE_DATA:
            #Clean the test cache data
            return
            

        processes = []
        now = timezone.localtime()
        if self.TEST_USER_NUMBER == 1:
            test_starttime = now
        else:
            test_starttime = now + timedelta(seconds = 10)
        test_endtime = test_starttime + timedelta(seconds = self.TEST_TIME)
        if cls.TEST_REQUESTS:
            print("Performance test will launch {} requests".format(cls.TEST_REQUESTS))
        else:
            print("Performance test will run from {} to {}".format(test_starttime.strftime("%Y-%m-%d %H:%M:%S"),test_endtime.strftime("%Y-%m-%d %H:%M:%S")))

        if self.TEST_USER_NUMBER == 1:
            self.run_test(None,0,test_starttime,test_endtime)
            print("Performance testing result of /sso/auth:")
            self.print_performancedata(cls.testusers[0].email,cls.authrequest)
        else:
            for i in range(self.TEST_USER_NUMBER):
                p_conn, c_conn = Pipe()
                processes.append((cls.testusers[i],p_conn,Process(target=self.run_test,args=(c_conn,i,test_starttime,test_endtime))))
    
            for testuser,p_conn,p in processes:
                p.start()
    
            first = True
            exs = []
            for testuser,p_conn,p in processes:
                result = p_conn.recv()
                p.join()
                if isinstance(result,Exception):
                    exs.append(result)
                    continue
                if first:
                    first = False
                    print("""Test Environment
    Tested Server       : {}
    Session Cache       : {}
    User Cache          : {}
    Default Cache       : {}
    
    Testing Server      : {}
    Test URL            : {}
    Test User Number    : {}
    Request Interval    : {} milliseconds
    Test Time           : {} seconds""".format(
                        cls.TESTED_SERVER,
                        settings.CACHE_SESSION_SERVER or settings.CACHE_SERVER,
                        settings.CACHE_USER_SERVER or settings.CACHE_SERVER,
                        settings.CACHE_SERVER,

                        cls.TESTING_SERVER,
                        "/sso/auth",
                        cls.TEST_USER_NUMBER,
                        cls.REQUEST_INTERVAL * 1000, 
                        cls.TEST_TIME
                    ))
                if cls.PRINT_USER_PERFORMANCE_DATA :
                    self.print_performancedata(testuser.email,result)
                self.merge_performancedata(result)


            print("================================================================================================")
            self.print_performancedata("Total({} users)".format(cls.TEST_USER_NUMBER),cls.authrequest)
            if exs:
                print("============================exceptions======================================================")

        
        
        
    def _post_teardown(self):
        pass

