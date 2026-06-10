import traceback
import time

from django.test import TestCase
from django.utils import timezone
from django.conf import settings

from . import utils
from . import testutils


class RedisClusterFailoverTestCase(testutils.RedisClusterTestCaseMixin,TestCase):
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
        super(RedisClusterFailoverTestCase,cls).setUpClass()
        #Get the cluster metadata
        #cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=True)


    def _test_masterserverfailover(self,testgroups=1,testrounds=4,crashedgroups=0):
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

    
            #prepare 1000 keys for each group
            keypattern = "testkey_{:010d}"
            index = 0
    
            groupsdata = [[]] * testgroups
    
            #prepare the data key for testing
            #generate the same amount of keys (cls.TEST_REDISCLUSTER_GROUP_KEYS) for each redis cluster group
            counter = 0
            while True:
                index += 1
                key = keypattern.format(index)
                node = cls._redis_client.get_node_from_key(key)
                
                groupmapdata = cls.groupmap[node.name]
                if groupmapdata[1] >= testgroups:
                    #the key is not hold by the tested redis cluster group, ignore
                    continue
                if len(groupsdata[groupmapdata[1]]) < cls.TEST_REDISCLUSTER_GROUP_KEYS:
                    counter += 1
                    groupsdata[groupmapdata[1]].append([key,1])
    
                if any(len(groupdata) < cls.TEST_REDISCLUSTER_GROUP_KEYS for groupdata in groupsdata ):
                    if counter % cls.TEST_REDISCLUSTER_GROUP_KEYS == 0:
                        print("Total {} keys generated.\n{}".format(counter,"\n".join( "{}={}".format(",".join([ node[0] for node in cls.groups[i]]),len(groupsdata[i])) for i in range(len(groupsdata)) )))
                    continue
                else:
                    print("Total {} keys generated.\n{}".format(counter,"\n".join( "{}={}".format(",".join([ node[0] for node in cls.groups[i]]),len(groupsdata[i])) for i in range(len(groupsdata)) )))
                    break
    
    
            if crashedgroups > 0:
                #shutdown the required redis cluster groups
                if crashedgroups >= 2:
                    #redis cluster only accept read operation if more than 1 redis group are down
                    #set the key before shutdown the redis servers
                    for i in range(testgroups):
                        group = self.groups[i]
                        groupdata = groupsdata[i]
                        for data in groupdata:
                            cls._redis_client.set(data[0],data[1])

                for i in range(len(cls.groups) - crashedgroups,len(cls.groups),1):
                    print("Shutdown redis cluster group:{}".format([node[0] for node in cls.groups[i]]))
                    for groupnode in cls.groups[i]:
                        cls.start_redisserver(groupnode[0],start=False)

                #wait node timeout
                timeout = cls.TEST_REDISCLUSTER_NODE_TIMEOUT / 1000 + 5
                print("Wait {} seconds to let redis cluster sync each other".format(timeout))
                time.sleep(timeout)
                cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=False,print_log=True)

            #test redis master server failover
            for j in range(testrounds):
                print("\n*************************Test Round {}*******************************".format(j + 1))
                if j > 0:
                    print("Wait 5 seconds and continue...")
                    time.sleep(5)
                #set a new data and shutdown/start the master server
                for i in range(testgroups):
                    group = self.groups[i]
                    groupdata = groupsdata[i]
                    #set new data
                    if crashedgroups < 2:
                        #redis cluster only accept read operation if more than 1 redis group are down
                        for data in groupdata:
                            data[1] += 1
                            cls._redis_client.set(data[0],data[1])
                        print("Successfully set the data for testing")

                    if j % 2 == 0:
                        print("Shutdown the master redis server({})".format(group[0]))
                        self.start_redisserver(group[0][0],start=False)
                        #now, redis cluster should already switch the master server to the second server
                        group[1][1] = True
                        #Move the stopped master server to the end , gurantee the first server in groups is the master server
                        group[0][1] = False
                        group[0][2] = False
                        group.append(group.pop(0))
                    else:
                        print("Start the redis server({})".format(group[1]))
                        self.start_redisserver(group[1][0],start=True)
                        group[1][2] = True
    
                #check whether redis cluster can return the correct data
                for i in range(testgroups):
                    group = self.groups[i]
                    groupdata = groupsdata[i]
    
                    for data in groupdata:
                        val = int(cls._redis_client.get(data[0]).decode())
                        self.assertEqual(data[1],val,msg="The data({1}) returned from the new master node is not the expected data({0})".format(data[1],val))
            
        finally:
            print("Restore the testing environment")
            cls.nodeids,cls.nodes,cls.groups,cls.groupmap = cls.get_cluster_metadata(start_all_server=True,print_log=False)


    def test_masterserverfailover_1group(self):
        print("\n\n*************************************************")
        print("Test the redis master server failover on one redis group")
        self._test_masterserverfailover(testgroups=1,testrounds=8)


    def test_masterserverfailover_2groups(self):
        print("\n\n*************************************************")
        print("Test the redis master server failover on two redis groups")
        self._test_masterserverfailover(testgroups=2,testrounds=8)

    def test_masterserverfailover_3groups(self):
        print("\n\n*************************************************")
        print("Test the redis master server failover on three redis groups")
        self._test_masterserverfailover(testgroups=3,testrounds=8)

    def test_masterserverfailover_1crashedgroup(self):
        print("\n\n*************************************************")
        print("Test the redis master server failover on two redis groups with one crashed redis group")
        self._test_masterserverfailover(crashedgroups=1,testrounds=8)

    def test_masterserverfailover_2crashedgroups(self):
        print("\n\n*************************************************")
        print("Test the redis master server failover on one redis group with two crashed redis groups")
        self._test_masterserverfailover(crashedgroups=2,testrounds=8)
