import math
import time
import random
from datetime import timedelta

from django.test import TestCase

from django.utils import timezone

from . import models
from . import utils
from authome.views.views import _check_tcontrol as check_tcontrol

from .basetest import BaseTestCase

class TrafficControlTestCase(BaseTestCase):
    def test_tcontrol_per_user(self):
        userlimit = 5
        userlimitperiod = 10
        client = "testuser01"
        clientip = "10.11.123.111"
        exempt = False
        tcontrol_config = models.TrafficControl(name="unitest_tcontrol01",userlimit=userlimit,userlimitperiod=userlimitperiod,enabled=True)
        tcontrol_config.clean()
        tcontrol_config,created = models.TrafficControl.objects.update_or_create(
            name=tcontrol_config.name,
            defaults={
                "userlimit":tcontrol_config.userlimit,
                "userlimitperiod":tcontrol_config.userlimitperiod,
                "enabled":tcontrol_config.enabled,
                "active":tcontrol_config.active
        })
        print("\n\nTest user traffic control, userlimit: {} , userlimitperiod: {}".format(userlimit,utils.format_timedelta(userlimitperiod)))
        try:
            now = timezone.localtime()
            today = now.replace(hour=0,minute=0,second=0,microsecond=0)
            seconds = int((now - today).total_seconds())
    
            starttime = today + timedelta(seconds = seconds + userlimitperiod - seconds % userlimitperiod)
            for i in range(2):
                waittime = starttime - timezone.localtime()
    
                print("{} Round Test: Start to run the test at {}. wait {}".format(i + 1,starttime.strftime("%Y-%m-%d %H:%M:%S.%f"),utils.format_timedelta(waittime)))
                allowed_requests = 0
                denied_requests = 0
                requests = math.ceil(userlimit * 1.5)
                time.sleep(waittime.total_seconds())
                for j in range(1,requests + 1,1):
                    result = check_tcontrol(tcontrol_config,clientip,client,exempt)
                    if j <= userlimit:
                        self.assertTrue(result[0],msg="{0}: The user has sent {2} requests which is less than the user limit({1}), should be allowed by traffic control".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),userlimit,j))
                        allowed_requests += 1
                    else:
                        self.assertFalse(result[0],msg="{0}: The user has sent {2} requests which is greater than the user limit({1}), should be denied by traffic control".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),userlimit,j))
                        self.assertEqual(result[1],"USER",msg="{0}: The user sent {2} requests which is greater than the user limit({1}), should be denied by user traffic control".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),userlimit,j))
                        denied_requests += 1
    
                print("Total requests: {}, allowed requests: {}, denied requests: {}".format(requests,allowed_requests,denied_requests))
    
                starttime = starttime + timedelta(seconds = userlimitperiod)
        finally:
            tcontrol_config.delete()
                    
    def test_tcontrol_per_ip(self):
        iplimit = 50
        iplimitperiod = 10
        users = 10
        clients = dict([("testuser{}".format(i),[0,0,0,0]) for i in range(1,users + 1,1)])
        clientip = "10.11.123.111"
        exempt = False
        tcontrol_config = models.TrafficControl(name="unitest_tcontrol02",iplimit=iplimit,iplimitperiod=iplimitperiod,enabled=True)
        tcontrol_config.clean()
        tcontrol_config,created = models.TrafficControl.objects.update_or_create(
            name=tcontrol_config.name,
            defaults={
                "iplimit":tcontrol_config.iplimit,
                "iplimitperiod":tcontrol_config.iplimitperiod,
                "enabled":tcontrol_config.enabled,
                "active":tcontrol_config.active
        })
        print("\n\nTest IP traffic control, iplimit: {} , iplimitperiod: {}".format(iplimit,utils.format_timedelta(iplimitperiod)))
        try:
            now = timezone.localtime()
            today = now.replace(hour=0,minute=0,second=0,microsecond=0)
            seconds = int((now - today).total_seconds())
    
            starttime = today + timedelta(seconds = seconds + iplimitperiod - seconds % iplimitperiod)
            for i in range(2):
                waittime = starttime - timezone.localtime()
    
                print("{} Round Test: Start to run the test at {}. wait {}".format(i + 1,starttime.strftime("%Y-%m-%d %H:%M:%S.%f"),utils.format_timedelta(waittime)))
                allowed_requests = 0
                denied_requests = 0
                exempt_requests = 0
                requests = math.ceil(iplimit * 2)
                time.sleep(waittime.total_seconds())
                for j in range(1,requests + 1,1):
                    client = "testuser{}".format(random.randint(1,users))
                    exempt = False if random.randint(0,1) == 0 else True
                    result = check_tcontrol(tcontrol_config,clientip,client,exempt)
                    clients[client][0] += 1
                    if j <= iplimit:
                        self.assertTrue(result[0],msg="{0}: The ip has sent {2} requests which is less than the ip limit({1}), should be allowed by traffic control".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),iplimit,j))
                        allowed_requests += 1
                        clients[client][1] += 1
                    elif exempt:
                        self.assertTrue(result[0],msg="{0}: The ip has sent {2} requests which is greater than the ip limit({1}), but the user is exempt for the traffic control, should be allowed by traffic control".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),iplimit,j))
                        exempt_requests += 1
                        clients[client][3] += 1
                    else:
                        self.assertFalse(result[0],msg="{0}: The ip has sent {2} requests which is greater than the ip limit({1}), should be denied by traffic control".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),iplimit,j))
                        self.assertEqual(result[1],"IP",msg="{0}: The ip has sent {2} requests which is greater than the ip limit({1}), should be denied by ip traffic control".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),iplimit,j))
                        denied_requests += 1
                        clients[client][2] += 1
    
                print("Total Requests: {}, Allowed Requests: {}, Denied Requests: {}, Exempt Requests: {}\n    {}".format(
                    requests,
                    allowed_requests,
                    denied_requests,
                    exempt_requests,
                    "\n    ".join([("{0} : Requests :{1}, Allowed Requests: {2}, Denied Requests: {3}, Exempt Requests: {4}".format("testuser{}".format(i),*clients["testuser{}".format(i)])) for i in range(1,users + 1,1)])
                ))
                for v in clients.values():
                    v[0] = 0
                    v[1] = 0
                    v[2] = 0
                    v[3] = 0
    
                starttime = starttime + timedelta(seconds = iplimitperiod)
        finally:
            tcontrol_config.delete()
                    
    def test_tcontrol_concurrency(self):
        est_processtime = 10000
        buckettime = 2000
        concurrency=10
        client = "testuser1"
        clientip = "10.11.123.111"
        exempt = False
        tcontrol_config = models.TrafficControl(name="unitest_tcontrol03",est_processtime=est_processtime,buckettime=buckettime,concurrency=concurrency,enabled=True)
        tcontrol_config.clean()
        tcontrol_config,created = models.TrafficControl.objects.update_or_create(
            name=tcontrol_config.name,
            defaults={
                "est_processtime":tcontrol_config.est_processtime,
                "buckettime":tcontrol_config.buckettime,
                "buckets":tcontrol_config.buckets,
                "concurrency":tcontrol_config.concurrency,
                "active":tcontrol_config.active,
                "enabled":tcontrol_config.enabled
        })
        print("\n\nTest user traffic control, est_processtime: {} milliseconds , buckettime: {} milliseconds, concurrency: {}".format(est_processtime,buckettime,concurrency))
        try:
            buckets = int(est_processtime / buckettime)
            totalbuckets = buckets * 4
            total_requests = 0
            total_allowed_requests = 0
            total_denied_requests = 0
            total_exempt_requests = 0

            current_requests = 0
            allowed_requests = 0
            denied_requests = 0
            exempt_requests = 0

            now = timezone.localtime()
            today = now.replace(hour=0,minute=0,second=0,microsecond=0)
            milliseconds = int((now - today).total_seconds() * 1000)
    
            starttime = today + timedelta(milliseconds = milliseconds + est_processtime - milliseconds % est_processtime)
            
            bucketrequests = []
            for bucketid in range(1,totalbuckets + 1,1):
                bucketrequests.append([0,0,0,0])
                if len(bucketrequests) > buckets:
                    current_requests -= bucketrequests[0][0] #allowed

                    allowed_requests -= bucketrequests[0][1]
                    denied_requests -= bucketrequests[0][2]
                    exempt_requests -= bucketrequests[0][3]
                    self.assertTrue(allowed_requests >= 0,"Allowed requests({}) should be zero or positive integer".format(allowed_requests))
                    self.assertTrue(denied_requests >= 0,"Denied requests({}) should be zero or positive integer".format(denied_requests))
                    self.assertTrue(exempt_requests >= 0,"Exempted requests({}) should be zero or positive integer".format(exempt_requests))

                    del bucketrequests[0]

                waittime = starttime - timezone.localtime()

                print("\n{} Bucket Test: Start to run the test at {}. wait {} milliseconds".format(bucketid,starttime.strftime("%Y-%m-%d %H:%M:%S.%f"),waittime.total_seconds() * 1000))
                time.sleep(waittime.total_seconds())

                for j in range(1,random.randint(1,math.ceil(concurrency * 3 / buckets)) + 1,1):
                    exempt = False if random.randint(0,1) == 0 else True
                    result = check_tcontrol(tcontrol_config,clientip,client,exempt)
                    total_requests += 1
                    current_requests += 1
                    bucketrequests[-1][0] += 1
                    if (allowed_requests + exempt_requests ) < concurrency:
                        total_allowed_requests += 1
                        allowed_requests += 1
                        bucketrequests[-1][1] += 1
                        self.assertTrue(result[0],msg="{0}:  Received {2} requests which is equal or less than the concurrency({1}), should be allowed by traffic control.result={3}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),concurrency,(allowed_requests + exempt_requests ),result))
                    elif exempt:
                        total_exempt_requests += 1
                        exempt_requests += 1
                        bucketrequests[-1][3] += 1
                        self.assertTrue(result[0],msg="{0}:  Received {2} requests which is equal or greater than the concurrency({1}), should be allowed by traffic control.result={3}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),concurrency,(allowed_requests + exempt_requests),result))
                    else:
                        total_denied_requests += 1
                        denied_requests += 1
                        bucketrequests[-1][2] += 1
                        self.assertFalse(result[0],msg="{0}:  already received {2} requests which is equal or greater than the concurrency({1}), should be denied by traffic control.result={3}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),concurrency,(allowed_requests + exempt_requests),result))
                        self.assertEqual(result[1],"CONCURRENCY",msg="{0}:  already received {2} requests which is equal or greater than the concurrency({1}), should be denied by concurrency traffic control.result={3}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),concurrency,(allowed_requests + exempt_requests),result))

                details="\n        ".join(["{0} : Requests :{1}, Allowed Requests: {2}, Denied Requests: {3}, Exempt Requests: {4}".format( (starttime - timedelta(milliseconds=(len(bucketrequests) - 1 - i) * buckettime)).strftime("%Y-%m-%d %H:%M:%S.%f"),*bucketrequests[i]) for i in range(len(bucketrequests))])
                print("{0}: Total Requests: {1}, Total Allowed Requests: {2}, Total Denied Requests: {3}, Total Exempt Requests: {4}\n    Current Requests: {5}, Allowed Requests: {6}, Denied Requests: {7}, Exempt Requests: {8}\n        {9}".format(
                    starttime.strftime("%Y-%m-%d %H:%M:%S.%f"),
                    total_requests,
                    total_allowed_requests,
                    total_denied_requests,
                    total_exempt_requests,
                    current_requests,
                    allowed_requests,
                    denied_requests,
                    exempt_requests,
                    details
                ))
    
                starttime = starttime + timedelta(milliseconds = buckettime)
        finally:
            tcontrol_config.delete()
                    
    def test_tcontrol(self):
        userlimit=10
        userlimitperiod=10

        iplimit=8
        iplimitperiod=4

        est_processtime = 1000
        buckettime = 200
        concurrency=10

        users = 3
        clients = dict([("testuser{}".format(i),[0,0,0,0,0]) for i in range(1,users + 1,1)])
        clientip = "10.11.123.111"
        exempt = False
        tcontrol_config = models.TrafficControl(
            name="unitest_tcontrol04",
            userlimit=userlimit,
            userlimitperiod=userlimitperiod,
            iplimit=iplimit,
            iplimitperiod=iplimitperiod,
            est_processtime=est_processtime,
            buckettime=buckettime,
            concurrency=concurrency,
            enabled=True
        )
        tcontrol_config.clean()
        tcontrol_config,created = models.TrafficControl.objects.update_or_create(
            name=tcontrol_config.name,
            defaults={
                "userlimit":tcontrol_config.userlimit,
                "userlimitperiod":tcontrol_config.userlimitperiod,
                "iplimit":tcontrol_config.iplimit,
                "iplimitperiod":tcontrol_config.iplimitperiod,
                "est_processtime":tcontrol_config.est_processtime,
                "buckettime":tcontrol_config.buckettime,
                "buckets":tcontrol_config.buckets,
                "concurrency":tcontrol_config.concurrency,
                "active":tcontrol_config.active,
                "enabled":tcontrol_config.enabled
        })
        print("\n\nTest user traffic control, est_processtime: {} milliseconds , buckettime: {} milliseconds, concurrency: {}".format(est_processtime,buckettime,concurrency))
        try:
            buckets = int(est_processtime / buckettime)
            if userlimitperiod >= iplimitperiod:
                totalbuckets = int(userlimitperiod * 1000 / buckettime) * 4
            else:
                totalbuckets = int(iplimitperiod * 1000 / buckettime) * 4

            total_requests = 0
            total_allowed_requests = 0
            total_denied_requests = 0
            total_exempt_requests = 0
            total_denied_by_others_requests = 0

            current_requests = 0
            allowed_requests = 0
            denied_requests = 0
            exempt_requests = 0

            ip_requests = 0
            ip_allowed_requests = 0
            ip_denied_requests = 0
            ip_exempt_requests = 0
            ip_denied_by_others_requests = 0

            now = timezone.localtime()
            today = now.replace(hour=0,minute=0,second=0,microsecond=0)
            milliseconds = int((now - today).total_seconds() * 1000)
    
            bucketstarttime = today + timedelta(milliseconds = milliseconds + est_processtime - milliseconds % est_processtime)
            userstarttime = today + timedelta(milliseconds = milliseconds + userlimitperiod * 1000 - milliseconds % (userlimitperiod * 1000))
            if userstarttime < bucketstarttime:
                userstarttime += timedelta(seconds=userlimitperiod)
            ipstarttime = today + timedelta(milliseconds = milliseconds + iplimitperiod * 1000 - milliseconds % (iplimitperiod * 1000))
            if ipstarttime < bucketstarttime:
                ipstarttime += timedelta(seconds=iplimitperiod)
            
            bucketrequests = []
            for bucketid in range(1,totalbuckets + 1,1):
                bucketrequests.append([0,0,0,0])
                if len(bucketrequests) > buckets:
                    current_requests -= bucketrequests[0][0] #allowed

                    allowed_requests -= bucketrequests[0][1]
                    denied_requests -= bucketrequests[0][2]
                    exempt_requests -= bucketrequests[0][3]
                    self.assertTrue(allowed_requests >= 0,"Allowed requests({}) should be zero or positive integer".format(allowed_requests))
                    self.assertTrue(denied_requests >= 0,"Denied requests({}) should be zero or positive integer".format(denied_requests))
                    self.assertTrue(exempt_requests >= 0,"Exempted requests({}) should be zero or positive integer".format(exempt_requests))

                    del bucketrequests[0]
                if userstarttime == bucketstarttime:
                    #clean user data
                    print("Start a new user traffic control period")
                    for v in clients.values():
                        v[0] = 0
                        v[1] = 0
                        v[2] = 0
                        v[3] = 0
                        v[4] = 0
                    userstarttime += timedelta(seconds=userlimitperiod)

                if ipstarttime == bucketstarttime:
                    print("Start a new ip traffic control period")
                    ip_requests = 0
                    ip_allowed_requests = 0
                    ip_denied_requests = 0
                    ip_exempt_requests = 0
                    ip_denied_by_others_requests = 0
                    ipstarttime += timedelta(seconds=iplimitperiod)


                now = timezone.localtime()
                waittime = bucketstarttime - now

                print("\n{}: Test: Start to run the test at {}. wait {} milliseconds".format(now.strftime("%Y-%m-%d %H:%M:%S.%f"),bucketstarttime.strftime("%Y-%m-%d %H:%M:%S.%f"),waittime.total_seconds() * 1000 ))
                time.sleep(waittime.total_seconds())

                bucket_test_requests = random.randint(1,math.ceil(concurrency * 5 / buckets))
                for j in range(1,bucket_test_requests + 1,1):
                    exempt = False if random.randint(0,1) == 0 else True
                    client = "testuser{}".format(random.randint(1,users))
                    result = check_tcontrol(tcontrol_config,clientip,client,exempt)
                    #check user limit
                    clients[client][0] += 1
                    total_requests += 1
                    ip_requests += 1

                    if exempt:
                        #exempted
                        clients[client][3] += 1
                    elif clients[client][1] >= userlimit:
                        #denied
                        clients[client][2] += 1
                        ip_denied_by_others_requests += 1
                        total_denied_by_others_requests += 1
                        self.assertFalse(result[0],msg="{0}: The user has sent {2} requests, {3} requests which is greater than the user limit({1}) are allowed, {4} requests are denied, {5} requests are exempted, {6} requests are denied because of others; should be denied by user traffic control".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),userlimit,*clients[client]))
                        self.assertEqual(result[1],"USER",msg="{0}: The user has sent {2} requests, {3} requests which is greater than the user limit({1}) are allowed, {4} requests are denied, {5} requests are exempted, {6} requests are denied because of others; should be denied by user traffic control".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),userlimit,*clients[client]))
                        continue
                    else:
                        #allowed
                        clients[client][1] += 1
                        
                    #check ip limit
                    if exempt:
                        #exempted
                        ip_exempt_requests += 1
                    elif (ip_allowed_requests + ip_exempt_requests) >= iplimit:
                        #denied
                        ip_denied_requests += 1
                        clients[client][1] -= 1
                        clients[client][4] += 1
                        total_denied_by_others_requests += 1
                        self.assertFalse(result[0],msg="{0}: The IP has sent {2} requests, {7} requests({3} allowed,{5} exmpted) which is greater than the ip limit({1}) are allowed, {4} requests are denied, {6} requests are denied because of others; should be denied by ip traffic control. {8}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),iplimit,ip_requests,ip_allowed_requests,ip_denied_requests,ip_exempt_requests,ip_denied_by_others_requests,(ip_allowed_requests + ip_exempt_requests),result))
                        self.assertEqual(result[1],"IP",msg="{0}: The IP has sent {2} requests, {7} requests({3} allowed,{5} exmpted) which is greater than the ip limit({1}) are allowed, {4} requests are denied, {6} requests are denied because of others; should be denied by ip traffic control. {8}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),iplimit,ip_requests,ip_allowed_requests,ip_denied_requests,ip_exempt_requests,ip_denied_by_others_requests,(ip_allowed_requests + ip_exempt_requests),result))

                        continue
                    else:
                        #allowed
                        ip_allowed_requests += 1
                        
                    #check currency
                    current_requests += 1
                    bucketrequests[-1][0] += 1
                    if (allowed_requests + exempt_requests ) < concurrency:
                        total_allowed_requests += 1
                        allowed_requests += 1
                        bucketrequests[-1][1] += 1
                        self.assertTrue(result[0],msg="{0}:  Received {2} requests which is equal or less than the concurrency({1}), should be allowed by traffic control.result={3}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),concurrency,(allowed_requests + exempt_requests),result))
                    elif exempt:
                        total_exempt_requests += 1
                        exempt_requests += 1
                        bucketrequests[-1][3] += 1
                        self.assertTrue(result[0],msg="{0}:  Received {2} requests which is euqal or greater than the concurrency({1}), should be allowed by traffic control.result={3}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),concurrency,(allowed_requests + exempt_requests),result))
                    else:
                        total_denied_requests += 1
                        denied_requests += 1
                        bucketrequests[-1][2] += 1

                        ip_denied_by_others_requests += 1
                        ip_allowed_requests -= 1

                        clients[client][1] -= 1
                        clients[client][4] += 1

                        self.assertFalse(result[0],msg="{0}:  already received {2} requests which is equal or greater than the concurrency({1}), should be denied by traffic control.result={3}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),concurrency,(allowed_requests + exempt_requests + 1),result))
                        self.assertEqual(result[1],"CONCURRENCY",msg="{0}:  already received {2} requests which is equal or greater than the concurrency({1}), should be denied by concurrency traffic control.result={3}".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),concurrency,(allowed_requests + exempt_requests + 1),result))

                clients_details="\n        ".join(["{0} : Requests :{1}, Allowed Requests: {2}, Denied Requests: {3}, Exempt Requests: {4}, Denined By Others Requests: {5}".format(k,*v) for k,v in clients.items()])
                bucket_details="\n            ".join(["{0} : Requests :{1}, Allowed Requests: {2}, Denied Requests: {3}, Exempt Requests: {4}".format( (bucketstarttime - timedelta(milliseconds=(len(bucketrequests) - 1 - i) * buckettime)).strftime("%Y-%m-%d %H:%M:%S.%f"),*bucketrequests[i]) for i in range(len(bucketrequests))])
                print("""{0}: {21} requests have been sent.
    User Traffic Control({1} - {2})
        {3}
    IP Traffic Control({4} - {5}): 
        Requests: {6}, Allowed Requests: {7}, Denied Requests: {8}, Exempt Requests: {9}, Denied By Others Requests: {10}
    Concurrency Traffic Control: Total Requests: {11}, Total Allowed Requests: {12}, Total Denied Requests: {13}, Total Exempt Requests: {14}, Total Denied By Others Requests: {15}
        Current Requests: {16}, Allowed Requests: {17}, Denied Requests: {18}, Exempt Requests: {19}
            {20}""".format(
                    bucketstarttime.strftime("%Y-%m-%d %H:%M:%S.%f"),

                    (userstarttime - timedelta(seconds=userlimitperiod)).strftime("%Y-%m-%d %H:%M:%S.%f"),
                    userstarttime.strftime("%Y-%m-%d %H:%M:%S.%f"),
                    clients_details,

                    (ipstarttime - timedelta(seconds=iplimitperiod)).strftime("%Y-%m-%d %H:%M:%S.%f"),
                    ipstarttime.strftime("%Y-%m-%d %H:%M:%S.%f"),
                    ip_requests,
                    ip_allowed_requests,
                    ip_denied_requests,
                    ip_exempt_requests,
                    ip_denied_by_others_requests,

                    total_requests,
                    total_allowed_requests,
                    total_denied_requests,
                    total_exempt_requests,
                    total_denied_by_others_requests,

                    current_requests,
                    allowed_requests,
                    denied_requests,
                    exempt_requests,

                    bucket_details,

                    bucket_test_requests
                ))
    
                bucketstarttime = bucketstarttime + timedelta(milliseconds = buckettime)
        finally:
            tcontrol_config.delete()
                    
