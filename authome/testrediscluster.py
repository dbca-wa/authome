from multiprocessing import Process,Pipe
import traceback
import time
import random
import json
import collections
import logging
from datetime import datetime,timedelta

from django.test import TestCase
from django.utils import timezone
from django.conf import settings
from django.core.cache import caches

from . import utils
from . import testutils


logger = logging.getLogger(__name__)

class DataMismatchException(Exception):
    pass

class RedisClusterTestCase(testutils.RedisClusterTestCaseMixin,TestCase):
    """
    Test redis cluster cache
    """
    TEST_REDISCLUSTER_GROUP_KEYS = utils.env("TEST_REDISCLUSTER_GROUP_KEYS",default=1000)
    TEST_REDISCLUSTER_PROCESSES_PER_GROUP = utils.env("TEST_REDISCLUSTER_PROCESSES_PER_GROUP",default=2)
    REQUEST_INTERVAL = utils.env("TEST_REDISCLUSTER_REQUEST_INTERVAL",default=1) #milliseconds
    TEST_TIME = utils.env("TEST_REDISCLUSTER_TIME",default=60) #seconds


    nodes = collections.OrderedDict()
    nodeids = collections.OrderedDict()
    #redis cluster groups, each group is a list which contain the group node
    groups = []
    #map between node and (group, the number of the nodes in the group)
    groupmap = collections.OrderedDict()

    requestdata = {
        "min_processtime" : None,
        "max_processtime" : None,
        "total_processtime" : None,
        "total_requests" : 0,
        "get_requests" : 0,
        "set_requests" : 0,
        "errors": {
        },
        "groups": {
        },
        "manage_servers":{

        }
    }


    @classmethod
    def setUpClass(cls):
        super(RedisClusterTestCase,cls).setUpClass()
        cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=True,print_log=True)

    def manage_redisserver(self,c_conn,group,test_starttime,test_endtime):
        """
        shutdown/restart the redis server
        """
        try:
            cls = self.__class__
            #wait until test starttime
            sleep_time = (test_starttime - timezone.localtime()).total_seconds()
            if sleep_time and sleep_time > 0:
                time.sleep(sleep_time)

            shutdown = False
            managed_node = None
            while (timezone.localtime() < test_endtime) :
                managed_node = group[0]
                #10 seconds passed since last time to shutdown/start server
                if group[0][2]:
                    #the first node is running.
                    #the first node should be the master, shutdown it
                    shutdown = True
                    self.start_redisserver(group[0][0],start=False)
                    #the first node should not be the master node anymore
                    group[0][1] = False
                    #the first node should not be running anymore
                    group[0][2] = False
                    #the second node should be the master right now, 
                    group[1][1] = True
                else:
                    #already shutdown before, restart it
                    shutdown = False
                    self.start_redisserver(group[0][0],start=True)
                    group[0][2] = True
                    #move the restarted redis server to last,  and  will stop/restart another redis server next time
                    group.append(group.pop(0))

                if managed_node[0] not in cls.requestdata["manage_servers"]:
                    cls.requestdata["manage_servers"][managed_node[0]] = {"shutdown":0,"start":0}
                if shutdown:
                    cls.requestdata["manage_servers"][managed_node[0]]["shutdown"] += 1
                else:
                    cls.requestdata["manage_servers"][managed_node[0]]["start"] += 1

                time.sleep(10)

            #The first group node has been shutdown, restart it .
            if not group[0][2]:
                #already shutdown before, restart it
                managed_node = group[0]
                self.start_redisserver(group[0][0],start=True)
                group.append(group.pop(0))

                if managed_node[0] not in cls.requestdata["manage_servers"]:
                    cls.requestdata["manage_servers"][managed_node[0]] = {"shutdown":0,"start":0}
                cls.requestdata["manage_servers"][managed_node[0]]["start"] += 1

    
            if c_conn:
                c_conn.send(cls.requestdata)
                c_conn.close()
        except Exception as ex:
            if c_conn:
                c_conn.send(ex)
                c_conn.close()
            else:
                raise

    def run_test(self,c_conn,group,groupdata,test_starttime,test_endtime):
        """
        Run the test for one cluster group
        group: a list of [node name,master?,running], the first element is always the master node
        """
        try:
            testutils.set_process_logconfig("./logs/{}.log".format(group[0][0].replace(":",".")))
            cls = self.__class__
            #wait until test starttime
            sleep_time = (test_starttime - timezone.localtime()).total_seconds()
            if sleep_time and sleep_time > 0:
                time.sleep(sleep_time)

            testingdata = {}
            getvalue=False
            last_shutdowntime = test_starttime
            while (timezone.localtime() < test_endtime) :
                starttime = timezone.localtime()
                key = groupdata[random.randrange(len(groupdata))]
                if key in testingdata:
                    getvalue = random.randrange(10) < 6
                else:
                    getvalue = False
                try:
                    if getvalue:
                        res = int(cls._redis_client.get(key))
                        if res != testingdata[key]:
                            raise DataMismatchException("{0} = {1}, expect {2}".format(key,res,testingdata[key]))
                    else:
                        val = testingdata.get(key,0) + 1
                        cls._redis_client.set(key,str(val),ex=86400)
                        testingdata[key] = val
                except DataMismatchException as ex:
                    cls.requestdata["errors"][ex.__class__.__name__] = cls.requestdata["errors"].get(ex.__class__.__name__,0) + 1
                except Exception as ex:
                    error = "{}({})".format(ex.__class__.__name__,traceback.format_exc())
                    errorkey = "{}({})".format(ex.__class__.__name__,str(ex))
                    logger.debug("Failed to {} {} from redis cluster group({}).error = {}".format("get" if getvalue else "set",key,group, error))
                    cls.requestdata["errors"][errorkey] = cls.requestdata["errors"].get(error,0) + 1

                endtime = timezone.localtime()
                processtime = (endtime - starttime).total_seconds()
                if not cls.requestdata["min_processtime"] or cls.requestdata["min_processtime"] >  processtime:
                    cls.requestdata["min_processtime"] = processtime
        
                if not cls.requestdata["max_processtime"] or  cls.requestdata["max_processtime"] <  processtime:
                    cls.requestdata["max_processtime"] = processtime
        
                cls.requestdata["total_requests"] += 1
                if getvalue:
                    cls.requestdata["get_requests"] += 1
                else:
                    cls.requestdata["set_requests"] += 1
                if not cls.requestdata["total_processtime"]:
                    cls.requestdata["total_processtime"] = processtime
                else:
                    cls.requestdata["total_processtime"] += processtime
    
                if cls.REQUEST_INTERVAL > 0:
                    time.sleep(cls.REQUEST_INTERVAL)
    
            if c_conn:
                c_conn.send(cls.requestdata)
                c_conn.close()
        except Exception as ex:
            if c_conn:
                c_conn.send(ex)
                c_conn.close()
            else:
                raise

    def merge_redisserver_managementdata(self,group,requestdata):
        cls = self.__class__
        cls.requestdata["manage_servers"].update(requestdata["manage_servers"])


    def merge_requestdata(self,group,requestdata):
        """
        group:list of [nodename,master?,running]
        """
        cls = self.__class__
        group = ",".join([node[0] for node in group])
        def _merge_requestdata(totaldata,requestdata):
            processtime = requestdata["min_processtime"]
            if not totaldata["min_processtime"] or totaldata["min_processtime"] >  processtime:
                totaldata["min_processtime"] = processtime
    
            processtime = requestdata["max_processtime"]
            if not totaldata["max_processtime"] or  totaldata["max_processtime"] <  processtime:
                totaldata["max_processtime"] = processtime
    
            totaldata["total_requests"] += requestdata["total_requests"]
            totaldata["get_requests"] += requestdata["get_requests"]
            totaldata["set_requests"] += requestdata["set_requests"]

            processtime = requestdata["total_processtime"]
            if not totaldata["total_processtime"]:
                totaldata["total_processtime"] = processtime
            else:
                totaldata["total_processtime"] += processtime

            totaldata["avg_processtime"] = totaldata["total_processtime"] / totaldata["total_requests"]
            for ex,counter in requestdata["errors"].items():
                totaldata["errors"][ex] = totaldata["errors"].get(ex,0) + counter

        if group not in cls.requestdata["groups"]:
            cls.requestdata["groups"][group] = {
                "min_processtime" : None,
                "max_processtime" : None,
                "total_processtime" : None,
                "total_requests" : 0,
                "get_requests" : 0,
                "set_requests" : 0,
                "errors": {
                }
            }

        _merge_requestdata(cls.requestdata["groups"][group],requestdata)

        _merge_requestdata(cls.requestdata,requestdata)

    def test_rediscluster(self):
        print("\n\n*************************************************")
        print("Test concurrent accessing with redis server crashing at any time")
        cls = self.__class__
        #prepare 1000 keys for each group
        keypattern = "testkey_{:010d}"
        index = 0

        groupsdata = [[]  for g in cls.groups]

        #prepare the data key for testing
        #generate the same amount of keys (cls.TEST_REDISCLUSTER_GROUP_KEYS) for each redis cluster group
        counter = 0
        while True:
            index += 1
            key = keypattern.format(index)
            node = cls._redis_client.get_node_from_key(key)
            
            group = cls.groupmap[node.name]
            if len(groupsdata[group[1]]) < cls.TEST_REDISCLUSTER_GROUP_KEYS:
                groupsdata[group[1]].append(key)

            if any(len(groupdata) < cls.TEST_REDISCLUSTER_GROUP_KEYS for groupdata in groupsdata ):
                counter += 1
                if counter % cls.TEST_REDISCLUSTER_GROUP_KEYS == 0:
                    print("Total {} keys generated.\n{}".format(counter,"\n".join( "{}={}".format(",".join([ node[0] for node in cls.groups[i]]),len(groupsdata[i])) for i in range(len(groupsdata)) )))
                continue
            else:
                print("Total {} keys generated.\n{}".format(counter,"\n".join( "{}={}".format(",".join([ node[0] for node in cls.groups[i]]),len(groupsdata[i])) for i in range(len(groupsdata)) )))
                break

        manage_redisserver_processes = []
        processes = []
        now = timezone.localtime()
        test_starttime = now + timedelta(seconds = 10)
        test_endtime = test_starttime + timedelta(seconds = self.TEST_TIME)
        keys_per_process = int(cls.TEST_REDISCLUSTER_GROUP_KEYS / cls.TEST_REDISCLUSTER_PROCESSES_PER_GROUP)
        start_index = 0
        end_index = 0

        #start the process to test redis cluster
        #each key is operated by only one process
        for i in range(len(cls.groups)):
            #Create the processes to shutdown/start redis server
            p_conn, c_conn = Pipe()
            manage_redisserver_processes.append((cls.groups[i],p_conn,Process(target=self.manage_redisserver,args=(c_conn,cls.groups[i],test_starttime,test_endtime))))

            for j in range(self.TEST_REDISCLUSTER_PROCESSES_PER_GROUP):
                start_index = keys_per_process * j
                if j == self.TEST_REDISCLUSTER_PROCESSES_PER_GROUP - 1:
                    end_index = cls.TEST_REDISCLUSTER_GROUP_KEYS
                else:
                    end_index = start_index + keys_per_process
                p_conn, c_conn = Pipe()
                processes.append((cls.groups[i],p_conn,Process(target=self.run_test,args=(c_conn,cls.groups[i],groupsdata[i][start_index:end_index],test_starttime,test_endtime))))
    
        print("""Begin to run the unit test.
    Start Time: {0}
    End Time: {1}
    Request Interval: {2} milliseconds
    Total Processes: {3}
    Testing Groups: {4}({5})
    Processes Per Group: {6}
    Keys Per Group: {7}
    Keys Per Process: {8}
    Process to manage redisserver: {9}""".format(
            utils.format_datetime(test_starttime),
            utils.format_datetime(test_endtime),
            cls.REQUEST_INTERVAL * 1000,
            len(processes),
            len(cls.groups),
            cls.groups,
            cls.TEST_REDISCLUSTER_PROCESSES_PER_GROUP,
            cls.TEST_REDISCLUSTER_GROUP_KEYS,
            keys_per_process,
            len(manage_redisserver_processes)

        ))
        #start the testing processes 
        for group,p_conn,p in manage_redisserver_processes:
            p.start()
    
        #start the testing processes 
        for group,p_conn,p in processes:
            p.start()

        #Wait the testing processes to finish and merge the testing result
        exs = []
        for group,p_conn,p in processes:
            result = p_conn.recv()
            p.join()
            if isinstance(result,Exception):
                exs.append(result)
                continue
            
            self.merge_requestdata(group,result)

        #Wait the redis management processes to finish and merge the testing result
        for group,p_conn,p in manage_redisserver_processes:
            result = p_conn.recv()
            p.join()
            if isinstance(result,Exception):
                exs.append(result)
                continue
            
            self.merge_redisserver_managementdata(group,result)

        #print the the testing result
        print("==========Test Result=================")
        print("==========Test Result=================")
        print(json.dumps(cls.requestdata,indent=4))

        if exs:
            print("===========Exceptions================")
            for ex in exs:
                print("{}:{}".format(ex.__class__.__name__,str(ex)))

        self.assertEqual(len(self.requestdata["errors"]) == 0 and not exs,True,msg="Some exceptions happened during testing")

