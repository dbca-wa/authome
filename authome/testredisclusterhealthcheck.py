import traceback
import re
import json
import time

from django.test import TestCase
from django.utils import timezone
from django.conf import settings

from . import utils
from . import testutils
from .serializers import JSONFormater

class RedisClusterHealthcheckTestCase(testutils.RedisClusterTestCaseMixin,TestCase):
    """
    Test redis cluster cache
    Required test env: Redis cluster with 3 groups, each group has one master server and one slave server
    """
    TEST_REDISCLUSTER_GROUP_KEYS = 1
    TEST_REDISCLUSTER_NODE_TIMEOUT = utils.env("TEST_REDISCLUSTER_NODE_TIMEOUT",15000) #milliseconds


    nodes = None
    nodeids = None
    #redis cluster groups, each group is a list which contain the group node
    groups = None
    #map between node and (group, the number of the nodes in the group)
    groupmap = None

    @classmethod
    def setUpClass(cls):
        super(RedisClusterHealthcheckTestCase,cls).setUpClass()
        #Get the cluster metadata
        #cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=True)


    def _test_ping(self,testgroups=1,testrounds=4,crashedgroups=0):
        cls = self.__class__

        try:
            #prepare the testing environment
            print("Prepare the testing environment")
            cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=True,print_log=True)

            if crashedgroups >= len(cls.groups):
                crashedgroups = len(cls.groups) - 1

            if testgroups <= 0:
                testgroups = len(cls.groups) - crashedgroups
            elif testgroups + crashedgroups > len(cls.groups):
                testgroups = len(cls.groups) - crashedgroups


            crashedgrouplist = []
    
            if crashedgroups > 0:
                #shutdown the required redis cluster groups
                for i in range(len(cls.groups) - crashedgroups,len(cls.groups),1):
                    print("Shutdown redis cluster group:{}".format([node[0] for node in cls.groups[i]]))
                    crashedgrouplist.append(i)
                    for groupnode in cls.groups[i]:
                        cls.start_redisserver(groupnode[0],start=False)

                #wait node timeout
                timeout = cls.TEST_REDISCLUSTER_NODE_TIMEOUT / 1000 + 5
                print("Wait {} seconds to let redis cluster sync each other".format(timeout))
                time.sleep(timeout)
                cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=False,print_log=True)

            crashednodenamemap = {}
            for j in range(testrounds):
                print("\n*************************Test Round {}*******************************".format(j + 1))
                if j > 0:
                    print("Wait 5 seconds and continue...")
                    time.sleep(5)
                for i in range(testgroups):
                    group = self.groups[i]

                    if j % 2 == 0:
                        print("Shutdown the master redis server({})".format(group[0]))
                        self.start_redisserver(group[0][0],start=False)
                        #now, redis cluster should already switch the master server to the second server
                        group[1][1] = True
                        #Move the stopped master server to the end , gurantee the first server in groups is the master server
                        group[0][1] = False
                        group[0][2] = False
                        crashednodenamemap[i] = crashednodenamemap.get(i,set())
                        crashednodenamemap[i].add(group[0][0])
                        group.append(group.pop(0))
                    else:
                        print("Start the redis server({})".format(group[1]))
                        self.start_redisserver(group[1][0],start=True)
                        group[1][2] = True
                        crashednodenamemap[i].remove(group[1][0])
                        if not crashednodenamemap[i]:
                            del crashednodenamemap[i]
                            
    
                healthstatus,healthdata = cls._cache.ping()
                print("Ping status={}\n{}".format(healthstatus,json.dumps(healthdata,indent=4,cls=JSONFormater)))
                #check whether the ping status is correct
                if crashedgrouplist:
                    self.assertEqual(healthstatus,False,"{} redis cluster groups are offline,the status of ping should be False".format(len(crashedgrouplist)))
                else:
                    self.assertEqual(healthstatus,True,"All redis cluster groups are online,the status of ping should be True".format(len(crashedgrouplist)))

                if not crashedgrouplist and not crashednodenamemap:
                    self.assertEqual(False  if healthdata.get("errors") else True,True,"All redis servers are online, the data of ping shoule not include any errors ".format(len(crashedgrouplist)))
                else:
                    for groupindex in crashedgrouplist:
                        nodelist = [node for node in  cls._redis_client.clustergroups[groupindex]]
                        msg = "The redis cluster group({}) is offline.".format(nodelist)
                        try:

                            healthdata.get("errors",[]).index(msg)
                        except ValueError as ex:
                            raise Exception("The group({}) is offline. the errors({}) of ping should contain the error '{}'".format(nodelist,healthdata.get("errors",[]),msg))

                    for groupindex,nodeset in crashednodenamemap.items():
                        groupnodelist = [node for node in  cls._redis_client.clustergroups[groupindex]]
                        crashednodelist = [node for node in groupnodelist if node in nodeset]
                        #print("{}  ,{}  ,{}".format(groupnodelist,nodeset,crashednodelist))
                        if len(nodeset) == 1:
                            msg = "The node({1}) in redis cluster group({0}) is offline.".format(groupnodelist,crashednodelist[0])
                        else:
                            msg = "The nodes({1}) in redis cluster group({0}) are offline.".format(groupnodelist,crashednodelist)
                        try:

                            healthdata.get("errors",[]).index(msg)
                        except ValueError as ex:
                            raise Exception("The nodes({}) in group({}) are offline. the errors({}) of ping should contain the error '{}'".format(crashednodelist,groupnodelist,healthdata.get("errors",[]),msg))

        finally:
            print("Restore the testing environment")
            cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=True,print_log=False)


    def test_ping_1group(self):
        print("\n\n*************************************************")
        print("Test ping on the redis master server on one redis group")
        self._test_ping(testgroups=1,testrounds=8)

    def test_ping_2groups(self):
        print("\n\n*************************************************")
        print("Test ping on the redis master server on two redis groups")
        self._test_ping(testgroups=2,testrounds=8)

    def test_ping_3groups(self):
        print("\n\n*************************************************")
        print("Test ping on the redis master server on three redis groups")
        self._test_ping(testgroups=3,testrounds=8)

    def test_ping_1crashedgroups(self):
        print("\n\n*************************************************")
        print("Test ping on the redis master server on two redis groups with one crashed redis group")
        self._test_ping(crashedgroups=1,testrounds=8)

    def test_ping_2crashedgroups(self):
        print("\n\n*************************************************")
        print("Test ping on the redis master server on one redis groups with two crashed redis groups")
        self._test_ping(crashedgroups=2,testrounds=8)


    def _test_serverstatus(self,testgroups=1,testrounds=4,crashedgroups=0):
        cls = self.__class__

        try:
            #prepare the testing environment
            print("Prepare the testing environment")
            cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=True,print_log=True)

            if crashedgroups >= len(cls.groups):
                crashedgroups = len(cls.groups) - 1

            if testgroups <= 0:
                testgroups = len(cls.groups) - crashedgroups
            elif testgroups + crashedgroups > len(cls.groups):
                testgroups = len(cls.groups) - crashedgroups


            crashedgrouplist = []
    
            if crashedgroups > 0:
                #shutdown the required redis cluster groups
                for i in range(len(cls.groups) - crashedgroups,len(cls.groups),1):
                    print("Shutdown redis cluster group:{}".format([node[0] for node in cls.groups[i]]))
                    crashedgrouplist.append(i)
                    for groupnode in cls.groups[i]:
                        cls.start_redisserver(groupnode[0],start=False)

                #wait node timeout
                timeout = cls.TEST_REDISCLUSTER_NODE_TIMEOUT / 1000 + 5
                print("Wait {} seconds to let redis cluster sync each other".format(timeout))
                time.sleep(timeout)
                cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=False,print_log=True)

            crashednodenamemap = {}
            for j in range(testrounds):
                print("\n*************************Test Round {}*******************************".format(j + 1))
                if j > 0:
                    print("Wait 5 seconds and continue...")
                    time.sleep(5)
                for i in range(testgroups):
                    group = self.groups[i]

                    if j % 2 == 0:
                        print("Shutdown the master redis server({})".format(group[0]))
                        self.start_redisserver(group[0][0],start=False)
                        #now, redis cluster should already switch the master server to the second server
                        group[1][1] = True
                        #Move the stopped master server to the end , gurantee the first server in groups is the master server
                        group[0][1] = False
                        group[0][2] = False
                        crashednodenamemap[i] = crashednodenamemap.get(i,set())
                        crashednodenamemap[i].add(group[0][0])
                        group.append(group.pop(0))
                    else:
                        print("Start the redis server({})".format(group[1]))
                        self.start_redisserver(group[1][0],start=True)
                        group[1][2] = True
                        crashednodenamemap[i].remove(group[1][0])
                        if not crashednodenamemap[i]:
                            del crashednodenamemap[i]
                            
    
                healthstatus, healthmsgs= cls._cache.server_status
                print("serverstatus status={}\n    {}".format(healthstatus,"\n    ".join(m for m in healthmsgs)))
                #check whether the serverstatus status is correct
                if crashedgrouplist or crashednodenamemap:
                    self.assertEqual(healthstatus,False,"{} redis cluster groups are offline,the status of serverstatus should be False".format(len(crashedgrouplist)))
                else:
                    self.assertEqual(healthstatus,True,"All redis cluster groups are online,the status of serverstatus should be True".format(len(crashedgrouplist)))

                crashednodelist = []
                for groupindex in crashedgrouplist:
                    crashednodelist.extend([node for node in  cls._redis_client.clustergroups[groupindex]])

                for groupindex,nodeset in crashednodenamemap.items():
                    groupnodelist = [node for node in  cls._redis_client.clustergroups[groupindex]]
                    crashednodelist.extend([node for node in groupnodelist if node in nodeset])


                for group in  cls._redis_client.clustergroups:
                    for groupnode in group:
                        host,port = groupnode.split(":",1)
                        nodemsg_re = re.compile("{}:{}.*\\:".format(host.replace(".","\\."),port))
                        if groupnode in crashednodelist:
                            status_re = re.compile("((status = Offline)|(error = ))")
                            errormsg = "Node({}) is offline, but the server message({}) doesn't match"
                        else:
                            status_re = re.compile("status = OK")
                            errormsg = "Node({}) is online, but the server message({}) doesn't match"

                        nodemsg = None
                        for msg in healthmsgs:
                            if nodemsg_re.search(msg):
                                nodemsg = msg
                                break
                        if nodemsg:
                            if not status_re.search(nodemsg):
                                raise Exception(errormsg.format(groupnode,nodemsg))
                        else:
                            raise Exception("Can't find the status message of the node({})".format(groupnode))

        finally:
            print("Restore the testing environment")
            cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=True,print_log=False)


    def test_serverstatus_1group(self):
        print("\n\n*************************************************")
        print("Test serverstatus on the redis master server on one redis group")
        self._test_serverstatus(testgroups=1,testrounds=8)

    def test_serverstatus_2groups(self):
        print("\n\n*************************************************")
        print("Test serverstatus on the redis master server on two redis groups")
        self._test_serverstatus(testgroups=2,testrounds=8)

    def test_serverstatus_3groups(self):
        print("\n\n*************************************************")
        print("Test serverstatus on the redis master server on three redis groups")
        self._test_serverstatus(testgroups=3,testrounds=8)

    def test_serverstatus_1crashedgroups(self):
        print("\n\n*************************************************")
        print("Test serverstatus on the redis master server on two redis groups with one crashed redis group")
        self._test_serverstatus(crashedgroups=1,testrounds=8)

    def test_serverstatus_2crashedgroups(self):
        print("\n\n*************************************************")
        print("Test serverstatus on the redis master server on one redis groups with two crashed redis groups")
        self._test_serverstatus(crashedgroups=2,testrounds=8)

