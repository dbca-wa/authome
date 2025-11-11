import logging
import math
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import models as django_models
from django.db.models.signals import pre_delete, pre_save, post_save, post_delete,m2m_changed
from django.dispatch import receiver

from ..cache import cache
from .. import signals
from .. import utils
from .. import lists
from .debugmodels import DebugLog
from .models import CacheableMixin,DbObjectMixin,defaultcache,ModelChange,UserGroup

logger = logging.getLogger(__name__)

class TrafficControl(CacheableMixin,DbObjectMixin,django_models.Model):
    _buckets = None
    _bucketslen = None
    _buckets_endid = None
    _buckets_endtime = None
    _buckets_begintime = None
    _buckets_fetchtime = None
    _buckets_totalrequests = 0

    _editable_columns = ("est_processtime","concurrency","iplimit","iplimitperiod","userlimit","userlimitperiod","enabled","active","buckettime","buckets","exempt_include","exempt_groups","block","timeout")
    name = django_models.SlugField(max_length=128,null=False,editable=True,unique=True)
    enabled = django_models.BooleanField(default=True,editable=True,help_text="Enable/disable the traffic control")
    active = django_models.BooleanField(default=False,editable=False)
    est_processtime = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The estimated processing time(milliseconds) used to calculate the concurrency requests") #millisecond
    buckettime = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="Declare the time period(milliseconds) of the bucket, the est_processtime and the total milliseconds of one day should be divided by this value.") #milliseconds
    buckets = django_models.PositiveIntegerField(default=0,null=False,editable=False)
    concurrency = django_models.PositiveIntegerField(default=0,null=False,editable=True)
    block = django_models.BooleanField(default=False,editable=True,help_text="If true, block the request until the running requests are less than the concurrency limit")

    iplimit = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The maximum requests per client ip which can be allowd in configure period")
    iplimitperiod = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The time period(seconds) configured for requests limit per client ip") #in seconds
    userlimit = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The maximum requests per user which can be allowd in configure period")
    userlimitperiod = django_models.PositiveIntegerField(default=0,null=False,editable=True,help_text="The time period(seconds) configured for requests limit per user") #in seconds
    exempt_include = django_models.BooleanField(default=True,editable=True,help_text="Exempt the traffic control for the user groups which is include/exclude the exempt_groups")
    exempt_groups = django_models.ManyToManyField(UserGroup,editable=True,blank=True)
    timeout = django_models.PositiveIntegerField(null=True,editable=True,help_text="The maximum seconds between the booking time and the current time.")
    modified = django_models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = django_models.DateTimeField(auto_now_add=timezone.now)

    class Meta:
        verbose_name_plural = "{}Traffic Control".format(" " * 7) 

    @property
    def bookingtimeout(self):
        return self.timeout or settings.TRAFFICCONTROL_BOOKINGTIMEOUT

    class BucketIds(object):
        def __init__(self,tcontrol,startid,length):
            self.tcontrol = tcontrol
            self.length = length
            self.startid = startid
            self._index = 0
        def __len__(self):
            return self.length
        def __iter__(self):
            self._index = -1

            return self

        def __next__(self):
            self._index += 1
            if self._index >= self.length:
                raise StopIteration()
            return self.tcontrol._normalize_bucketid(self.startid + self._index)

        def __str__(self):
            return str([d for d in self])

        def __repr__(self):
            return str([d for d in self])

    class BookingBucketIds(object):
        def __init__(self,tcontrol,startid,length):
            self.tcontrol = tcontrol
            self.length = length
            self.startid = startid
            self._index = 0
        def __len__(self):
            return self.length
        def __iter__(self):
            self._index = -1

            return self

        def __next__(self):
            self._index += 1
            if self._index >= self.length:
                raise StopIteration()
            return self.tcontrol._normalize_bucketid(self.startid + self._index)

        def __str__(self):
            return str([d for d in self])

        def __repr__(self):
            return str([d for d in self])

    class NonExpiredBucketIds(object):
        def __init__(self,tcontrol,length):
            self.tcontrol = tcontrol
            self.length = length
            self.bucketid = None
            self.endbucketid = self.tcontrol._normalize_bucketid(self.tcontrol._buckets_endid - self.tcontrol._bucketslen - 1 + self.length)
        def __len__(self):
            return self.length
        def __iter__(self):
            self.bucketid = self.tcontrol._normalize_bucketid(self.tcontrol._buckets_endid - self.tcontrol._bucketslen - 1)
            return self

        def __next__(self):
            if self.bucketid == self.endbucketid:
                raise StopIteration()
            try:
                return self.bucketid
            finally:
                self.bucketid = self.tcontrol._normalize_bucketid(self.bucketid + 1)

    class Buckets(object):
        def __init__(self,tcontrol,expiredbuckets = 0):
            self.tcontrol = tcontrol
            if expiredbuckets == 0:
                self.expiredbuckets_beginindex = None
            else:
                self.expiredbuckets_beginindex = self.tcontrol._bucketslen - expiredbuckets - 1
            self.bucket = None
            self.index = None
            
        def __iter__(self):
            self.index = 0
            if self.expiredbuckets_beginindex is not None and self.expiredbuckets_beginindex == self.index:
                self.bucket = [self.tcontrol._buckets_begintime,self.tcontrol._normalize_bucketid(self.tcontrol._buckets_endid - self.tcontrol._bucketslen + 1),"Expired"]
            else:
                self.bucket = [self.tcontrol._buckets_begintime,self.tcontrol._normalize_bucketid(self.tcontrol._buckets_endid - self.tcontrol._bucketslen + 1),self.tcontrol._buckets[self.index]]
            return self

        def __next__(self):
            if self.index >= self.tcontrol._bucketslen:
                raise StopIteration()
            if self.bucket[1] == self.tcontrol._buckets_endid:
                if self.bucket[0] != self.tcontrol._buckets_endtime:
                    raise Exception("buckets_begintime({}) is incorrect.".format(self.tcontrol._buckets_begintime.strftime("%Y-%m-%d %H:%M:%S.%f"),self.tcontrol._buckets_endtime.strftime("%Y-%m-%d %H:%M:%S.%f"),self.tcontrol._bucketslen))
            try:
                return self.bucket
            finally:
                self.index += 1
                if self.index < self.tcontrol._bucketslen:
                    if self.expiredbuckets_beginindex is not None and self.index >= self.expiredbuckets_beginindex and self.index < self.tcontrol._bucketslen - 1:
                        self.bucket = [self.bucket[0] + timedelta(milliseconds=self.tcontrol.buckettime),self.tcontrol._normalize_bucketid(self.bucket[1] + 1),"Expired"]
                    else:
                        self.bucket = [self.bucket[0] + timedelta(milliseconds=self.tcontrol.buckettime),self.tcontrol._normalize_bucketid(self.bucket[1] + 1),self.tcontrol._buckets[self.index]]

    @classmethod
    def get_model_change_cls(self):
        return TrafficControlChange

    def clean(self):
        super().clean()
        timediff = math.floor(settings.TRAFFICCONTROL_TIMEDIFF.microseconds / 1000)

        if self.userlimitperiod and 86400 % self.userlimitperiod != 0:
            raise ValidationError("The total seconds of a day(86400) should be divided by userlimitperiod.")
        
        if self.iplimitperiod and 86400 % self.iplimitperiod != 0:
            raise ValidationError("The total seconds of a day(86400) should be divided by iplimitperiod.")
        
        if self.est_processtime and self.est_processtime > 21600000:
            raise ValidationError("The estimate processtime can't be larger than 6 hours")

        if self.buckettime and self.est_processtime:
            #find the maximum buckets which can be used to uniquely identity each bucket
            #the maximum buckets should meet the following requirements
            #1. the whold day can be divided by the total times of the mximum buckets.
            #2. The bucket must be safely expired before it can be reused.normally, the bucket expire time is the bucket time plus 5 seconds
            if self.buckettime < timediff or self.est_processtime % self.buckettime != 0 or 86400000 % self.buckettime != 0:
                raise ValidationError("The buckettime should be larger than {}; Both the total milleseconds of one day(86400000) and estimated processing time({}) must be divided by the value of buckettime.".format(timediff,self.est_processtime))

            if int(self.est_processtime / self.buckettime) > settings.TRAFFICCONTROL_MAX_BUCKETS:
                raise ValidationError("The buckettime is too small, will slow the performance, it should be larger than {}".format( math.ceil(self.est_processtime / settings.TRAFFICCONTROL_MAX_BUCKETS)))

            totalbucketstime = self.est_processtime +  (7200000 + self.est_processtime - 7200000 % self.est_processtime)

            minbuckets = int(totalbucketstime / self.buckettime)

            while 86400000 % totalbucketstime != 0 and int((86400000 % totalbucketstime) / self.buckettime) < minbuckets:
                totalbucketstime += self.buckettime

            self.buckets = int(totalbucketstime / self.buckettime)
        else:
            self.buckets = 0
        self.active = True if (self.enabled and ((self.concurrency > 0 and self.est_processtime > 0 and self.buckettime) or (self.iplimit > 0 and self.iplimitperiod > 0) or (self.userlimit > 0 and self.userlimitperiod > 0))) else False

    def _normalize_bucketid(self,bucketid):
        if bucketid < 0:
            return bucketid + self.buckets
        elif bucketid < self.buckets:
            return bucketid
        else :
            return bucketid % self.buckets

    def _log_buckets_error(self,warnings,msg):
        log = DebugLog.tcontrol(DebugLog.TRAFFIC_CONTROL_ERROR,self.name,None,None,"{11}.\ntcontrol={0} , est_processtime={1} milliseconds , buckettime={2} milliseconds , concurrency={3}\nbuckets_begintime={4} , buckets_beginid={5} , buckets_endtime={6} , buckets_endid={7} , buckets_fetchtime={8} , totalrequests={9}\nbuckets={10}".format(
            self.name,
            self.est_processtime,
            self.buckettime,
            self.concurrency,
            self._buckets_begintime.strftime("%Y-%m-%dT%H:%M:%S.%f") if self._buckets_begintime else None,
            self._normalize_bucketid(self._buckets_endid - self._bucketslen + 1) if self._buckets_endid else None,
            self._buckets_endtime.strftime("%Y-%m-%dT%H:%M:%S.%f") if  self._buckets_endtime else None,
            self._buckets_endid,
            self._buckets_fetchtime.strftime("%Y-%m-%dT%H:%M:%S.%f") if self._buckets_fetchtime else None,
            self._buckets_totalrequests,
            self._buckets,
            msg
        ),save=False)
        warnings.append(log)

    @property
    def prefetch_buckets(self):
        """
        Prefetch all buckets for future booking
        """
        if self._bucketslen:
            return self._bucketslen
        else:
            return self.est_processtime / self.buckettime


    def get_checkingbuckets(self,warnings,today,milliseconds_in_day,exempt):
        """
        today: 
        milliseconds: milliseconds in today
        get the checking bucket status for concurrency checking
        return
            current checking:(True, endbuckettime,endbucketid,retrieving required bucketids,total requests of non-expired buckets)
            exceed concurrency:(True, None,None,None,total requests)
            future booking  :(False , endbuckettime,endbucketid,the begintime of the first retrieveing buckets,the endtime,the bucketid of the first retrieveing buckets,retrieving required bucketids,)
        """
        #get the milliseconds in totalbucketstime
        try:
            milliseconds = (milliseconds_in_day % self._totalbucketstime)
        except:
            self._totalbucketstime = self.buckets * self.buckettime
            milliseconds = (milliseconds_in_day % self._totalbucketstime)

        #get the id and time of the current bucket
        currentbucketid = math.floor(milliseconds / self.buckettime)
        currentbuckettime = today + timedelta(milliseconds=milliseconds_in_day - milliseconds % self.buckettime )

        if self._buckets_endtime is None:
            #_buckets is not initialized before. initialize it.
            self._buckets = [0] * int(self.est_processtime / self.buckettime)
            self._bucketslen = len(self._buckets)
            self._buckets_endtime = currentbuckettime
            self._buckets_endid = currentbucketid
            self._buckets_begintime = self._buckets_endtime - timedelta(milliseconds=self.est_processtime - self.buckettime)
            self._buckets_totalrequests = 0
            if self._bucketslen == 1:
                self._buckets_begintime = self._buckets_endtime
                return [True,self._buckets_endtime,self._buckets_endid,None,0]
            else:
                self._buckets_begintime = self._buckets_endtime - timedelta(milliseconds=self.est_processtime - self.buckettime)
                return [True,self._buckets_endtime,self._buckets_endid,self.BucketIds(self,self._normalize_bucketid(self._buckets_endid - self._bucketslen + 1),self._bucketslen - 1),0]
        elif self._buckets_endtime <= currentbuckettime:
            #check current concurrency
            #get how many buckets in self._buckets are outdated.
            outdatedbuckets = int(((currentbuckettime - self._buckets_endtime).total_seconds()) * 1000 / self.buckettime)
            if outdatedbuckets >= self._bucketslen:
                #all buckets in self._bucketslen are outdated
                #reset all requests in buckets to 0
                for i in range(self._bucketslen):
                    self._buckets[i] = 0
                self._buckets_totalrequests = 0
                self._buckets_endtime = currentbuckettime
                self._buckets_endid = currentbucketid
                self._buckets_fetchtime = None
                if self._bucketslen == 1:
                    self._buckets_begintime = self._buckets_endtime
                    return [True,self._buckets_endtime,self._buckets_endid,None,0]
                else:
                    self._buckets_begintime = self._buckets_endtime - timedelta(milliseconds=self.est_processtime - self.buckettime)
                    return [True,self._buckets_endtime,self._buckets_endid,self.BucketIds(self,self._normalize_bucketid(self._buckets_endid - self._bucketslen + 1),self._bucketslen - 1),0]
            elif outdatedbuckets > 0:
                #some buckets in self._buckets are outdated.
                #remove the outdated buckets, and append the same number of empty buckets to self._buckets
                for i in range(outdatedbuckets):
                    self._buckets_totalrequests -= self._buckets[i]
                    self._buckets[i] = 0
                self._buckets.extend(self._buckets[0:outdatedbuckets])
                del self._buckets[0:outdatedbuckets]

                self._buckets_endtime = currentbuckettime
                self._buckets_endid = currentbucketid
                if self._bucketslen == 1:
                    self._buckets_begintime = self._buckets_endtime
                else:
                    self._buckets_begintime = self._buckets_endtime - timedelta(milliseconds=self.est_processtime - self.buckettime)

            #now self._buckets has up-to-date buckets 
            if not self._buckets_fetchtime:
                #all buckets are expired or never fetch before.
                return [True,self._buckets_endtime,self._buckets_endid,self.BucketIds(self,self._normalize_bucketid(self._buckets_endid - self._bucketslen + 1),self._bucketslen - 1),0]
            else:
                if self._buckets_totalrequests >= self.concurrency:
                    #already hit the concurrency limit
                    #the reason why the total requests can be greater than concurrency is the time gap between increment and decrement for exceed concurrency requests. but eventually the total requests should be not greater than concurrency.
                    #reach the limit, need future booking
                    if not self.block and not exempt:
                        #future booking not allowed
                        return [True,None,None,None,self._buckets_totalrequests]
                else:
                    #don't reach the limit,
                    #try to find how many buckets need to be fetched again.
                    expiredbuckets_starttime = self._buckets_fetchtime - settings.TRAFFICCONTROL_TIMEDIFF
                    if expiredbuckets_starttime >= self._buckets_endtime:
                        #all buckets data are not expired
                        return [True,self._buckets_endtime,self._buckets_endid,None,self._buckets_totalrequests - self._buckets[-1]]
                    else:
                        #some buckets are expired
                        expiredbuckets = math.ceil(((self._buckets_endtime - expiredbuckets_starttime).total_seconds() * 1000) / self.buckettime)
                        if expiredbuckets >= self._bucketslen - 1:
                            #all buckets are expired
                            self._buckets_fetchtime = None
                            return [True,self._buckets_endtime,self._buckets_endid,self.BucketIds(self,self._normalize_bucketid(self._buckets_endid - self._bucketslen + 1),self._bucketslen - 1),0]
                        else:
                            #some buckets are expired
                            return [True,self._buckets_endtime,self._buckets_endid,self.BucketIds(self,self._normalize_bucketid(self._buckets_endid - expiredbuckets),expiredbuckets),self.get_runningrequests(0,self._bucketslen - 1 - expiredbuckets)]
        elif not self.block and not exempt:
            #have some requests in the waiting queue.
            #future booking not allowed
            return [True,None,None,None,self.concurrency]

        #have some requests in the waiting queue.
        #return the metadata to start booking a running spot in the future
        if self._buckets_totalrequests >= self.concurrency:
            #the total requests in the self._buckets already reach the limit. should book the running spot from the next bucket
            #move forward the buckets until the requests of the left bucket is not zero
            i = 0
            while i < self._bucketslen:
                if self._buckets[0]:
                    break
                else:
                    i += 1
                    self._buckets.append(0)
                    del self._buckets[0]

            self._buckets_endtime += timedelta(milliseconds=self.buckettime * i)
            self._buckets_endid = self._normalize_bucketid(self._buckets_endid + i)
            self._buckets_begintime = self._buckets_endtime - timedelta(milliseconds=self.est_processtime - self.buckettime)
            if i > self._bucketslen:
                self._log_buckets_error(warnings,"get_checkingbuckets: All buckets in memory are empty")
                raise Exception("All buckets are empty")
            #the total requests in the self._buckets  reach the limit.
            return [False,self._buckets_endtime,self._buckets_endid,self._buckets_endtime + timedelta(milliseconds=self.buckettime),self._buckets_endtime + timedelta(milliseconds=self.buckettime * self.prefetch_buckets),self._normalize_bucketid(self._buckets_endid + 1),self.BookingBucketIds(self,self._normalize_bucketid(self._buckets_endid + 1),self.prefetch_buckets)]
        else:
            #the total requests in the self._buckets doesn't reach the limit.
            #don't reach the limit, retriving ${_bucketslen} buckets from the bucket self._buckets_endid  for future booking.
            return [False,self._buckets_endtime,self._buckets_endid,self._buckets_endtime,self._buckets_endtime + timedelta(milliseconds=self.buckettime * (self.prefetch_buckets - 1)),self._buckets_endid,self.BookingBucketIds(self,self._buckets_endid,self.prefetch_buckets)]

    def set_buckets(self,warnings,buckettime,bucketid,bucketrequests,fetchtime,expiredbuckets_requests=None):
        """
        For current concurrency checking called after checking whether concurrency is exceed or not
        Called after fetching the expired buckets and increment the current bucket
        Should consider the race condition among threads, auth2 servers; adjust the bucket requests if required before call this method

        buckettime, bucketid: the self._buckets_endtime and self._buckets_endid when calling method 'get_checkingbuckets' to get the metadata for concurrency checking
        The possible out-of-sync scenario can happen because of race condition and delay running.
        1. the current status of self._buckets is different with the status of self._buckets when calling method 'get_checkingbuckets' to get the metadata for concurrency checking because more requests are pocessed between get_checkingbuckets and set_buckets in multithreads environment
        2. the endtime of self._buckets is not match the endtime of current time bucket because the time gap between get_checkingbuckets and set_buckets is greater than self._buckettime
        3. If the fetchtime in memory is later than the fetchtime parameters, means the memory has the latest status and ignore the status parameters
        """
        if bucketrequests < 0:
            self._log_buckets_error(warnings,"set_buckets: current_bucket_requsts({0}) is less than 0. buckettime={1} , bucketid={2}, fetchtime={3}, expiredbuckets_requests={4}".format(
                bucketrequests,
                buckettime.strftime("%Y-%m-%dT%H:%M:%S.%f"),
                bucketid,
                fetchtime.strftime("%Y-%m-%dT%H:%M:%S.%f"),
                expiredbuckets_requests
            ))
        if self._buckets_fetchtime and self._buckets_fetchtime > fetchtime:
            #the self._buckets data was set by the request which fetch the data from cache later than fetchtime
            #return directly.
           return 

        outdatedbuckets = 0
        if buckettime != self._buckets_endtime:
            #the status of the self._buckets has been changed by other requests
            #find how many buckets are outdated in the previous self_buckets, 
            #during setting the fetched buckets data, will ignore the outdated buckets
            outdatedbuckets = int(((self._buckets_endtime - buckettime).total_seconds()) * 1000 / self.buckettime)
            if expiredbuckets_requests:
                if len(expiredbuckets_requests) > outdatedbuckets: 
                    #still have some buckets can be set
                    expiredbuckets_requests = lists.ROListSlice(expiredbuckets_requests,outdatedbuckets,len(expiredbuckets_requests) - outdatedbuckets)
                else:
                    expiredbuckets_requests = []

        #set the latest fetchtime
        self._buckets_fetchtime = fetchtime
        #set the expired buckets requests
        if expiredbuckets_requests:
            index = self._bucketslen - 1 - len(expiredbuckets_requests)
            for i in range(len(expiredbuckets_requests)):
                if expiredbuckets_requests[i] != self._buckets[index]:
                    self._buckets_totalrequests += expiredbuckets_requests[i] - self._buckets[index]
                    self._buckets[index] = expiredbuckets_requests[i]
                index += 1
        #set the bucketrequests
        if outdatedbuckets == 0:
            self._buckets_totalrequests += bucketrequests - self._buckets[-1]
            self._buckets[-1] = bucketrequests
        elif outdatedbuckets < self._bucketslen:
            self._buckets_totalrequests += bucketrequests - self._buckets[-1 - outdatedbuckets]
            self._buckets[-1 - outdatedbuckets] = bucketrequests

    def set_bookingbucket(self,warnings,buckettime,bucketid,requests,totalrequests):
        """
        Set the already booked bucket data
        Return Ture if set the data to memory  ;return False if memory is already in latest status
        """
        up2date = True
        if buckettime != self._buckets_endtime:
            #race condition, some other clients have booked some bucket positions, the data should already be in latest status
            return False
        elif self._buckets[-1] >= requests:
            #race condition, some other clients have booked some bucket positions, the data should already be in latest status
            up2date = False
        else:
            up2date = True
            self._buckets_totalrequests += requests - self._buckets[-1]
            self._buckets[-1] = requests
        if totalrequests >= self.concurrency:
            #reach or exceed the limit and also the bucket endtime is not changed, move the buckets forward
            i = 0
            while i < self._bucketslen:
                i += 1
                self._buckets.append(0)
                if self._buckets[0]:
                    self._buckets_totalrequests -= self._buckets[0]
                    del self._buckets[0]
                    break
                else:
                    del self._buckets[0]
    
            self._buckets_endtime += timedelta(milliseconds=self.buckettime * i)
            self._buckets_endid = self._normalize_bucketid(self._buckets_endid + i)
            self._buckets_begintime = self._buckets_endtime - timedelta(milliseconds=self.est_processtime - self.buckettime)
        
            if i > self._bucketslen:
                self._log_buckets_error(warnings,"set_bookingbuckets: All buckets in memory are empty")
                raise Exception("All buckets are empty")
        return up2date

    def set_bookedbuckets(self,warnings,buckets_endtime,bookedbuckets_begintime,bookedbuckets_endtime,bookedbuckets_beginid,bookedbucketids,bookedbuckets_requests,fetchtime):
        """
        should consider the race condition, multiple clients try to increment the value at the same time, so it is possible the value is greater than the final value; if that happens, adjust the requests value
        If fetchtime in memory is later than the fetchtime parameter, the memory has the latest status
        Return True if can book the running position from the end bucket; otherwise return false to retrieveing the futurebuckets again
        """
        if not self._buckets_fetchtime or self._buckets_fetchtime <= fetchtime:
            #update the memory status of the buckets
            self._buckets_fetchtime = fetchtime
            if buckets_endtime != self._buckets_endtime:
                #after get_checkingbuckets, some book requests changes the endtime.
                #ignore all the data before self._buckets_endtime
                while bookedbuckets_begintime < self._buckets_endtime:
                    if bookedbucketids and bookedbuckets_beginid == bookedbucketids[0]:
                        #not skipped, delete the data
                        del bookedbucketids[0]
                        del bookedbuckets_requests[0]
                    bookedbuckets_begintime += timedelta(milliseconds=self.buckettime)
                    bookedbuckets_beginid = self._normalize_bucketid(bookedbuckets_beginid + 1)
    
            #set bookedbuckets's requests to memory

            #found the index of the right bucket which request is not zero
            endindex = len(bookedbuckets_requests) - 1
            while endindex >= 0:
                if not bookedbuckets_requests[endindex]:
                    #the right buckets data is 0.
                    endindex -= 1
                else:
                    #the right buckets data is not 0.
                    break
    
            if endindex >= 0:
                #found some booked requests
                j = 0
                #set the endbucket of self._buckets if required
                if bookedbuckets_begintime == self._buckets_endtime:
                    #bookedbuckets is from the end bucket of self._buckets
                    if bookedbuckets_beginid == bookedbucketids[j]:
                        self._buckets_totalrequests += bookedbuckets_requests[j] - self._buckets[-1]
                        if self._buckets_totalrequests  <= self.concurrency:
                            self._buckets[-1] = bookedbuckets_requests[j]
                        else:
                            #exceed the concurrency, caused by the time gap between increment and decrement. adjust the requests
                            self._buckets[-1] = bookedbuckets_requests[j] - (self._buckets_totalrequests - self.concurrency)
                            if self._buckets[-1] >= 0:
                                self._buckets_totalrequests = self.concurrency
                            else: 
                                self._log_buckets_error(warnings,"set_bookedbuckets: The requests({1}} of the bucket({0}) is less than 0.".format(j,self._buckets[-1]))
                                self._buckets_totalrequests -= self._buckets[-1]
                                self._buckets[-1] = 0 
                        j += 1
    
                #set next buckets if have
                if j < len(bookedbucketids):
                    #have booking in the future buckets, requests in the bucket list should reach the concurrency
                    #buckettime is the time of the previous bucket of the first non-overlap bucket
                    if self._buckets_totalrequests > self.concurrency:
                        self._log_buckets_error(warnings,"set_bookedbuckets: The running requests({1}) is greater than the concurrency({0}),bookedbucketids={2} , bookedbuckets_requests={3} , bookedbuckets_beginid={4} , bookedbuckets_begintime={5}".format(self.concurrency,self._buckets_totalrequests,bookedbucketids,bookedbuckets_requests,bookedbuckets_beginid,bookedbuckets_begintime.strftime("%Y-%m-%dT%H:%M:%S.%f")))
    
                    while j <= endindex:
                        self._buckets_endid = self._normalize_bucketid(self._buckets_endid + 1)
                        self._buckets_endtime += timedelta(milliseconds=self.buckettime)
                        self._buckets_begintime += timedelta(milliseconds=self.buckettime)
                        if self._buckets_endid != bookedbucketids[j]:
                            #skipped future buckets, the corresponding current bucket should have no requests
                            if self._buckets[0] != 0:
                                self._log_buckets_error(warnings,"set_bookedbuckets: The requests of the skipped bucket({0}) in memory should be 0.".format(j))
                                self._buckets_totalrequests -= self._buckets[0]
                            self._buckets.append(0)
                            del self._buckets[0]
                            continue
                        elif self._buckets[0] < bookedbuckets_requests[j]: 
                            #maybe it is caused by race condition, the requests in memory should be not less than the requests in redis
                            self._buckets.append(self._buckets[0])
                            del self._buckets[0]
                        elif self._buckets[0] > bookedbuckets_requests[j]:
                            if j == endindex:
                                #the last bucket
                                diff = self._buckets[0] - bookedbuckets_requests[j]
                                self._buckets.append(bookedbuckets_requests[j])
                                self._buckets_totalrequests -= diff
                                del self._buckets[0]
                            else:
                                #not the last bucket, caused by race condition
                                #use the memory data
                                self._log_buckets_error(warnings,"set_bookedbuckets: The requests({1}) of the non-tail bucket({0}) should be not less than the requests({2}) of the first bucket.".format(j,bookedbuckets_requests[j],self._buckets[0]))
                                self._buckets.append(self._buckets[0])
                                del self._buckets[0]
                        else:
                            self._buckets.append(self._buckets[0])
                            del self._buckets[0]
                        j += 1

                    if self._buckets_totalrequests >= self.concurrency and endindex < len(bookedbuckets_requests) - 1:
                        #already reach the limit, still have some buckets with zero requests at the right side. add them to the buckets
                        j = endindex + 1
                        while j < len(bookedbuckets_requests):
                            j += 1
                            self._buckets.append(self._buckets[0])
                            del self._buckets[0]
                        counter = len(bookedbuckets_requests) - endindex - 1
                        self._buckets_endid = self._normalize_bucketid(self._buckets_endid + counter)
                        self._buckets_endtime += timedelta(milliseconds=self.buckettime * counter)
                        self._buckets_begintime += timedelta(milliseconds=self.buckettime * counter)
            elif self._buckets_totalrequests >= self.concurrency:
                #alrdady reach the limit
                #can't find any buckets with non-zero requests. move the buckets to the next availabe bucket
                i = 0
                while i < self._bucketslen:
                    i += 1
                    self._buckets.append(0)
                    if self._buckets[0]:
                        self._buckets_totalrequests -= self._buckets[0]
                        del self._buckets[0]
                        break
                    else:
                        del self._buckets[0]

                self._buckets_endtime += timedelta(milliseconds=self.buckettime * i)
                self._buckets_endid = self._normalize_bucketid(self._buckets_endid + i)
                self._buckets_begintime = self._buckets_endtime - timedelta(milliseconds=self.est_processtime - self.buckettime)
                if i > self._bucketslen:
                    self._log_buckets_error(warnings,"get_checkingbuckets: All buckets in memory are empty")
                    raise Exception("All buckets are empty")


        if self._buckets_totalrequests >= self.concurrency:
            #reach the limit, fetch the future buckets
            return False
        else:
            #don't reach the limit. try to book the running spot from the endbucket
            return True
        
    def get_runningrequests(self,start,length):
        """
        should be called after set_current_buckets , expired_previous_buckets and set_previous_buckets 
        """
        if self._buckets is None:
            return 0

        if length == 1:
            return self._buckets[start]
        elif length == self._bucketslen:
            return self._buckets_totalrequests
        elif length <= int(self._bucketslen / 2):
            result = 0
            for data in lists.ROListSlice(self._buckets,start,length):
                if data:
                    result += data
        else:
            result = self._buckets_totalrequests
            if start > 0:
                for data in lists.ROListSlice(self._buckets,0,start):
                    if data:
                        result -= data
            for data in lists.ROListSlice(self._buckets,start + length,self._bucketslen - start - length):
                if data:
                    result -= data

        return result

    @property
    def exempt_usergroups(self):
        try:
            return self._exempt_usergroups
        except:
            exempt_usergroups = []
            for group in self.exempt_groups.all():
                exempt_usergroups.append(group.id)

            self._exempt_usergroups = exempt_usergroups
            return self._exempt_usergroups
            
        

    def is_exempt(self,email):
        if not self.exempt_usergroups:
            #the data should be cached in method "refresh_cache"
            return False

        return any(g in UserGroup.find_groups(email)[2] for g in self._exempt_usergroups)
        

    @classmethod
    def refresh_cache(cls):
        """
        Popuate the data and save them to cache
        """
        logger.debug("Refresh TrafficControl cache")
        refreshtime = timezone.localtime()
        size = 0

        tmp_tcontrols = {}
        for obj in TrafficControl.objects.filter(active=True).prefetch_related("exempt_groups"):
            if obj.active:
                _groups = obj.exempt_usergroups
                tmp_tcontrols[obj.id] = obj
        #don't need the map items(tcontrol.id,tcontrol) for auth2 server without tcontrol support
        tcontrols = tmp_tcontrols if settings.TRAFFICCONTROL_SUPPORTED else {}
        for obj in TrafficControlLocation.objects.all():
            size += 1
            tcontrol = tmp_tcontrols.get(obj.tcontrol_id)

            if tcontrol and tcontrol.active :
                #cache the user groups
                tcontrols[(obj.domain,obj.location,obj.method)] = tcontrol
        cache.tcontrols = (tcontrols,size,refreshtime)
        return refreshtime

    

class TrafficControlLocation(DbObjectMixin,django_models.Model):
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4

    METHOD_CHOICES = (
        (GET,"GET"),
        (POST,"POST"),
        (PUT,"PUT"),
        (DELETE,"DELETE")
    )
    METHODS = {
        "GET":GET,
        "POST":POST,
        "PUT":PUT,
        "DELETE":DELETE
    }

    _editable_columns = ("domain","method","location")
    tcontrol = django_models.ForeignKey(TrafficControl, on_delete=django_models.CASCADE,editable=False,null=False)
    domain = django_models.CharField(max_length=128,null=False,editable=True)
    method = django_models.PositiveSmallIntegerField(choices=METHOD_CHOICES,null=False,editable=True)
    location = django_models.CharField(max_length=256,null=False,editable=True)
    modified = django_models.DateTimeField(auto_now=timezone.now,db_index=True)
    created = django_models.DateTimeField(auto_now_add=timezone.now)

    class Meta:
        verbose_name_plural = "{}Traffic Control Locations"
        unique_together = [["domain","method","location"]]



if defaultcache:
    class TrafficControlChange(ModelChange):
        key = "tcontrol_last_modified"
        model = TrafficControlLocation

        @classmethod
        def get_cachetime(cls):
            return cache._tcontrols_ts

        @classmethod
        def get_cachesize(cls):
            return cache._tcontrolss_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._tcontrol_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            cache.refresh_tcontrol_cache()

        @staticmethod
        @receiver(post_save, sender=TrafficControl)
        def post_save_tcontrol(sender,*args,**kwargs):
            TrafficControlChange.change()

        @staticmethod
        @receiver(post_delete, sender=TrafficControl)
        def post_delete_tcontrol(sender,*args,**kwargs):
            TrafficControlChange.change()

        @staticmethod
        @receiver(m2m_changed, sender=TrafficControl.exempt_groups.through)
        def m2m_changed_tcontrol(sender,*args,**kwargs):
            TrafficControlChange.change()

        @staticmethod
        @receiver(post_save, sender=TrafficControlLocation)
        def post_save_location(sender,*args,**kwargs):
            TrafficControlChange.change()

        @staticmethod
        @receiver(post_delete, sender=TrafficControlLocation)
        def post_delete_location(sender,*args,**kwargs):
            TrafficControlChange.change()

        @classmethod
        def status(cls):
            status = super().status()
            if status[0] != UP_TO_DATE:
                return status

            try:
                last_refreshed = cls.get_cachetime()
                o = TrafficControl.objects.all().order_by("-modified").first()
                if o:
                    if last_refreshed and last_refreshed >= o.modified:
                        return (UP_TO_DATE,last_refreshed)
                    elif o.modified > cls.last_synced:
                        return (OUT_OF_SYNC,last_refreshed)
                else:
                    return (UP_TO_DATE,last_refreshed)
    
                return (UP_TO_DATE,last_refreshed)
            except:
                #Failed, assume it is up to date
                DebugLog.warning(DebugLog.ERROR,None,None,None,None,"Failed to get the status of the model 'TrafficControl' from cache.{}".format(traceback.format_exc()))
                return (UP_TO_DATE,last_refreshed)
else:
    class TrafficControlChange(ModelChange):
        model = TrafficControlLocation

        @classmethod
        def get_cachetime(cls):
            return cache._tcontrols_ts

        @classmethod
        def get_cachesize(cls):
            return cache._tcontrols_size

        @classmethod
        def get_next_refreshtime(cls):
            return cache._tcontrol_cache_check_time.next_runtime

        @classmethod
        def refresh_cache_if_required(cls):
            cache.refresh_tcontrol_cache()

        @classmethod
        def status(cls):
            status = super().status()
            if status[0] != UP_TO_DATE:
                return status

            try:
                last_refreshed = cls.get_cachetime()
                o = TrafficControl.objects.all().order_by("-modified").first()
                if o:
                    if last_refreshed and last_refreshed >= o.modified:
                        return (UP_TO_DATE,last_refreshed)
                    elif o.modified > cls.last_synced:
                        return (OUT_OF_SYNC,last_refreshed)
                else:
                    return (UP_TO_DATE,last_refreshed)
    
                return (UP_TO_DATE,last_refreshed)
            except:
                #Failed, assume it is up to date
                DebugLog.warning(DebugLog.ERROR,None,None,None,None,"Failed to get the status of the model 'TrafficControl' from cache.{}".format(traceback.format_exc()))
                return (UP_TO_DATE,last_refreshed)

