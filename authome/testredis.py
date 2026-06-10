import traceback
import time

from django.test import TestCase
from django.utils import timezone
from django.conf import settings

from . import utils
from . import testutils
from .cache import get_usercache,get_usercache_by_email,get_defaultcache


class RedisTestCase(TestCase):
    """
    Test redis cache
    """


    def test_cache(self,testgroups=1,testrounds=4,crashedgroups=0):
        cache = get_defaultcache()
        for k,v in [("test1",1),("test2",2),("test3",3)]:
            cache.set(k,v)
            cachedv = cache.get(k)
            self.assertEqual(cachedv,v,msg="The data({1}) of key({0}) returned from the redis is the expected data({2})".format(k,cachedv,v))
            cache.delete(k)
            cachedv = cache.get(k)
            self.assertIsNone(cachedv,msg="The key({0}) was deleted, but still get the value({1}) from redis".format(k,cachedv))

    def test_usercache(self,testgroups=1,testrounds=4,crashedgroups=0):
        for userid,user in [(1,{"name":"test1@dbca.wa.gov.au"}),(2,{"name":"test2@dbca.wa.gov.au"}),(3,{"name":"test3@dbca.wa.gov.au"}),(4,{"name":"test4@dbca.wa.gov.au"})]:
            userkey = settings.GET_USER_KEY(userid)
            usercache = get_usercache(userid)
            usercache.set(userkey,user)
            cacheduser = usercache.get(userkey)
            self.assertEqual(cacheduser,user,msg="The user({1}) of userid({0}) returned from the redis is the expected data({2})".format(userkey,cacheduser,user))
            usercache.delete(userkey)
            cacheduser = usercache.get(userkey)
            self.assertIsNone(cacheduser,msg="The userid({0}) was deleted, but still get the user({1}) from redis".format(userkey,cacheduser))

    def test_useremailcache(self,testgroups=1,testrounds=4,crashedgroups=0):
        for useremail,userid in [("test1@dbca.wa.gov.au",1),("test2@dbca.wa.gov.au",2),("test3@dbca.wa.gov.au",3),("test4@dbca.wa.gov.au",4)]:
            userkey = settings.GET_USEREMAIL_KEY(useremail)
            usercache = get_usercache_by_email(useremail)
            usercache.set(userkey,userid)
            cacheduserid = usercache.get(userkey)
            self.assertEqual(cacheduserid,userid,msg="The user({1}) of userid({0}) returned from the redis is the expected data({2})".format(userkey,cacheduserid,userid))
            usercache.delete(userkey)
            cacheduserid = usercache.get(userkey)
            self.assertIsNone(cacheduserid,msg="The userid({0}) was deleted, but still get the user({1}) from redis".format(userkey,cacheduserid))
