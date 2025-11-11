import logging
import os
from datetime import timedelta,datetime
import time
import urllib.parse
import traceback
import math

from django.conf import settings
from django.core.cache import caches
from django.utils import timezone
from django.template.response import TemplateResponse

from ..cache import cache
from .views import defaultcache,get_absolute_url,_get_userflow_pagelayout,forbidden
from .. import utils
from .. import models
from authome.models import DebugLog

logger = logging.getLogger(__name__)

def forbidden_tcontrol(request):
    """
    View method for path '/sso/forbidden_tcontrol'
    can also be called from other view method
    Provide a consistent,customized forbidden page.
    """
    tcontrol = request.GET.get("tcontrol")
    if tcontrol:
        url = get_absolute_url(request.GET.get("path") or request.get_full_path(),request.get_host())
        parsed_url = utils.parse_url(url)
        domain = parsed_url["domain"]
        path = parsed_url["path"]

        page_layout,extracss = _get_userflow_pagelayout(request,domain)
        context = {"body":page_layout,"extracss":extracss,"path":path,"url":url.format(domain,path),"domain":domain}
        try:
            tcontrol = tcontrol.split("|")
            tcontrol[1] = cache.tcontrols.get(int(tcontrol[1])) or None
            if len(tcontrol) == 4:
                tcontrol[3] = int(tcontrol[3])

            if tcontrol[0] == "USER":
                if tcontrol[1]:
                    context["msg"] = "You have sent too many requests({}) in {}, please try again after {}".format(tcontrol[2],utils.format_timedelta(tcontrol[1].userlimitperiod) ,utils.format_timedelta(tcontrol[3]))
                else:
                    context["msg"] = "You have sent too many requests({}), please try again after {}".format(tcontrol[2],utils.format_timedelta(tcontrol[3]))
            else:
                if settings.DEBUG:
                    if tcontrol[0] == "IP":
                        if tcontrol[1]:
                            context["msg"] = "Too many requests({}) have been sent in {}, please try again after {}.".format(tcontrol[2],utils.format_timedelta(tcontrol[1].userlimitperiod) ,utils.format_timedelta(tcontrol[3]))
                        else:
                            context["msg"] = "Too many requests({}) have been sent, please try again after {}.".format(tcontrol[2],utils.format_timedelta(tcontrol[3]))
                    elif tcontrol[2] == "TIMEOUT":
                        context["msg"] = "Timeout! You should wait at least {} seconds to finish this request".format(tcontrol[3])
                    else: 
                        context["msg"] = "Too many requests({}) are running, please wait a few seconds and try again.".format(tcontrol[3])
                else:
                    if tcontrol[0] == "IP":
                        if tcontrol[1]:
                            context["msg"] = "Too many requests have been sent in {}, please try again after {}".format(utils.format_timedelta(tcontrol[1].userlimitperiod) ,utils.format_timedelta(tcontrol[3]))
                        else:
                            context["msg"] = "Too many requests have been sent, please try again after {}".format(utils.format_timedelta(tcontrol[3]))
                    elif tcontrol[2] == "TIMEOUT":
                        context["msg"] = "Timeout! You should wait at least {} seconds to finish this request".format(tcontrol[3])
                    else:
                        context["msg"] = "Too many requests are running, please wait a few seconds and try again."
        except:
            context["msg"] = "Too many requests are running, please wait a few seconds and try again."

        return TemplateResponse(request,"authome/tcontrol.html",context=context)
    else:
        return forbidden(request)

_tcontrolcaches = {}
def _tcontrolcache(key,cache = False):
    if settings.TRAFFICCONTROL_CACHE_SERVERS == 1:
        return caches[settings.TRAFFICCONTROL_CACHE_ALIAS]
    elif settings.TRAFFICCONTROL_CACHE_SERVERS == 0:
        return None
    elif cache:
        try:
            return _tcontrolcaches[key]
        except KeyError as ex:
            c = caches[settings.TRAFFICCONTROL_CACHE_ALIAS(key)]
            _tcontrolcaches[key] = c
            return c
    else:
        return caches[settings.TRAFFICCONTROL_CACHE_ALIAS(key)]

def _log_tcontrol(cacheclient,logkey,expiretime):
    try:
        return cacheclient.execute_command("set",logkey,"1","NX","EX",expiretime)
    except:
        #cache is not available, disable log
        return False

_currentuserlimitkeys = {}
_currentiplimitkeys = {}
_currentbuckets = {}

#begin for debug
import socket
_req_seq = 0
_processid = None
def _get_processid():
    global _processid
    if not _processid:
        _processid = "{}-{}".format(socket.gethostname(),os.getpid())

    return _processid

#end for debug

def _check_tcontrol(tcontrol,clientip,client,exempt,test=False,checktime=None):
    exception = None
    warnings = []

    #begin for debug
    global _req_seq
    _req_seq += 1
    requestid = _req_seq
    _bucket_endtime_before=None
    _endbucket_requests_before=None
    def _requestid():
        return "{0} Request-{1}-{2}:".format(timezone.localtime().strftime("%Y-%m-%d %H:%M:%S.%f"),_get_processid(),requestid,tcontrol.name,client,clientip,exempt)
 
    def _bucketsstatus(label=""):
        if tcontrol._buckets:
            return "Buckets of tcontrol{}: buckets={} , begintime={} , endtime={} , endid={} , total requests={}, fetchtime={}".format("({})".format(label) if label else "",tcontrol._buckets,tcontrol._buckets_begintime.strftime("%Y-%m-%d %H:%M:%S.%f"),tcontrol._buckets_endtime.strftime("%Y-%m-%d %H:%M:%S.%f"),tcontrol._buckets_endid,tcontrol._buckets_totalrequests,tcontrol._buckets_fetchtime.strftime("%Y-%m-%d %H:%M:%S.%f") if tcontrol._buckets_fetchtime else None)
        else:
            return "Buckets of tcontrol{}: buckets=[] , begintime=None , endtime=None , endid=None , total requests=None, fetchtime=None".format("({})".format(label) if label else "")

    def _debug(msg,previous_bucketstatus):
        print("\n====BEGIN====\n{} : {} \n    {}\n    {}\n====END====\n".format(_requestid(),msg,previous_bucketsstatus,_bucketsstatus()))
    #end for debug

    try:
        userrequests = None
        iprequests = None
        totalrequests = None
        starttime = timezone.localtime()
        bookingtime = None

        #check traffic control for client
        userlimitkey = None

        if not client and (tcontrol.iplimit <= 0 or tcontrol.iplimitperiod <= 0):
            #iplimit is not enabled. use client ip as client
            client = clientip

        if not exempt and client and tcontrol.userlimit > 0 and tcontrol.userlimitperiod > 0:
            try:
                now = checktime or timezone.localtime()
                today = now.replace(hour=0,minute=0,second=0,microsecond=0)
                milliseconds = math.floor((now - today).total_seconds() * 1000)
                keyprefix = "{}_{}_{}".format(tcontrol.name,tcontrol.userlimitperiod,client)
                userlimitkey = settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_{}".format(keyprefix,math.floor(milliseconds / (tcontrol.userlimitperiod * 1000))))
                usercacheclient = _tcontrolcache(keyprefix).redis_client
                #increase the requests and set the expire time if required
                currentuserlimitkey = _currentuserlimitkeys.get(tcontrol.id)
                if not currentuserlimitkey:
                    currentuserlimitkey = [userlimitkey,False]
                    _currentuserlimitkeys[tcontrol.id] = currentuserlimitkey
                elif currentuserlimitkey[0] != userlimitkey:
                    currentuserlimitkey[0] = userlimitkey
                    currentuserlimitkey[1] = False
                if currentuserlimitkey[1]:
                    userrequests = usercacheclient.incr(userlimitkey)
                else:
                    pipe = usercacheclient.pipeline()
                    pipe.incr(userlimitkey)
                    pipe.expire(userlimitkey,tcontrol.userlimitperiod + 5)
                    userrequests,_ = pipe.execute()
                    currentuserlimitkey[1] = True

                if userrequests > tcontrol.userlimit:
                    if userrequests == tcontrol.userlimit + 1:
                        if _log_tcontrol(usercacheclient,settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_{}_debuglog".format(tcontrol.name,client)),1800):
                            #log interval half an hour
                            DebugLog.tcontrol(DebugLog.USER_TRAFFIC_CONTROL,tcontrol.name,clientip,client,"The user({}) sent too many requests({}) in {}".format(client,userrequests,utils.format_timedelta(tcontrol.userlimitperiod)))
                    #exceed the user limit
                    return [False,"USER",userrequests,tcontrol.userlimitperiod - int(milliseconds / 1000) % tcontrol.userlimitperiod]
            except Exception as ex:
                traceback.print_exc()
                exception = ex

    
        iplimitkey = None
        if clientip and tcontrol.iplimit > 0 and tcontrol.iplimitperiod > 0:
            try:
                now = checktime or timezone.localtime()
                today = now.replace(hour=0,minute=0,second=0,microsecond=0)
                milliseconds = math.floor((now - today).total_seconds() * 1000)
                keyprefix = "{}_{}_{}".format(tcontrol.name,tcontrol.iplimitperiod,clientip)
                iplimitkey = settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_{}".format(keyprefix,math.floor(milliseconds / (tcontrol.iplimitperiod * 1000))))
                ipcacheclient = _tcontrolcache(keyprefix).redis_client
                #increase the requests and set the expire time if required
                currentiplimitkey = _currentiplimitkeys.get(tcontrol.id)
                if not currentiplimitkey:
                    currentiplimitkey = [iplimitkey,False]
                    _currentiplimitkeys[tcontrol.id] = currentiplimitkey
                elif currentiplimitkey[0] != iplimitkey:
                    currentiplimitkey[0] = iplimitkey
                    currentiplimitkey[1] = False

                if currentiplimitkey[1]:
                    iprequests = ipcacheclient.incr(iplimitkey)
                else:
                    pipe = ipcacheclient.pipeline()
                    pipe.incr(iplimitkey)
                    pipe.expire(iplimitkey,tcontrol.iplimitperiod + 5)
                    iprequests,_ = pipe.execute()
                    currentiplimitkey[1] = True

                if iprequests > tcontrol.iplimit:
                    if iprequests == tcontrol.iplimit + 1:
                        if _log_tcontrol(ipcacheclient,settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_{}_debuglog".format(tcontrol.name,clientip)),1800):
                            #log interval half an hour
                            DebugLog.tcontrol(DebugLog.IP_TRAFFIC_CONTROL,tcontrol.name,clientip,client,"The IP address({}) sent too many requests({}) in {}".format(clientip,iprequests,utils.format_timedelta(tcontrol.iplimitperiod)))
                    #exceed the ip limit
                    if not exempt:
                        if userlimitkey:
                            #decrease the user limits which was added before
                            try:
                                usercacheclient.decr(userlimitkey)
                            except:
                                #ignore
                                pass
                        return [False,"IP",iprequests,tcontrol.iplimitperiod - int(milliseconds / 1000) % tcontrol.iplimitperiod]
            except Exception as ex:
                traceback.print_exc()
                exception = ex

        #check the concurrency
        """
        concurrency checking is hard to guarantee the total running requests is acurate and not exceed the concurrency.
        1. First the est_processtime is an assumption, can't guarantee that every request spents just the est_processtime
        2. For the booking requests, if the browser or client cancel the request. the request will never run, but it is still in the running queue and count an pending request
        3. if a bucket with request 3 is exceed the concurrency, the coming request will increment the requests first and then desc the request later, if one or more request increment the requests and then another request retrieves the buckets, the requests retrievied by the request will be greater than 3. but if this happens, means the total requests is exceed the concurrency
        4. race condition, for example, est_processtime has 10 buckets, the concurrency is 10.
          the requests in bucket 0 to 8 is 9 requests, a request with the endbucket 9 get the permission to run in bucket 9, now the requests in bucket 0 to 8 is 9 requests, and the requests in bucket 0 to 9 is 10 requests; another request with the endbucket 8 get the permission to run in bucket 8, now the requests in bucket 0 to 8 is already 10 requests, and the requests in bucket 0 to 9 is 11 requests which is exceed the limit.
        5. Because the time delay between increment and decrement, so the data fetched from the cache will be greater than the final result, should do some adjustment in memory
        """
        if tcontrol.concurrency > 0 and tcontrol.est_processtime > 0:
            try:
                pipe = None
                now = checktime or timezone.localtime()
                today = now.replace(hour=0,minute=0,second=0,microsecond=0)
                milliseconds = math.floor((now - today).total_seconds() * 1000)
                expiredbuckets_requests = 0

                #begin for debug
                previous_bucketsstatus = _bucketsstatus("Previous")
                #end for debug
                checkingbuckets = tcontrol.get_checkingbuckets(warnings,today,milliseconds,exempt)

                cacheclient = _tcontrolcache(tcontrol.name,cache=True).redis_client

                succeed = False
                while not succeed:
                    if checkingbuckets[0]:
                        #the concurrency is not exceed the limit.
                        _,buckettime,bucketid,expired_buckets,nonexpired_requests = checkingbuckets
                        #begin for debug
                        _debug("After get_checkingbuckets. buckets_endtime={} , buckets_endid= {} , expired_buckets={} , nonexpired_requsts={}".format(buckettime.strftime("%Y-%m-%d %H:%M:%S.%f") if buckettime else None,bucketid,expired_buckets,nonexpired_requests),previous_bucketsstatus)
                        #end for debug
                        if buckettime is None:
                            #exceed the concurrency
                            totalrequests = tcontrol.concurrency + 1
                        else:
                            key = settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_{}".format(tcontrol.name,bucketid))
                            #increase the requests and set the expire time if required
                            currentbucket = _currentbuckets.get(tcontrol.id)
                            if not currentbucket:
                                currentbucket = [buckettime,False]
                                _currentbuckets[tcontrol.id] = currentbucket
                            elif currentbucket[0] != buckettime:
                                currentbucket[0] = buckettime
                                currentbucket[1] = False
                            pipe = cacheclient.pipeline()
                            pipe.time() 
                            pipe.incr(key)
                            if currentbucket[1]:
                                if expired_buckets:
                                    pipe.mget([settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_{}".format(tcontrol.name,d)) for d in expired_buckets])
                                    fetchtime,requests,expiredbuckets_requests = pipe.execute()
                                else:
                                    fetchtime,requests = pipe.execute()
                            else:
                                if expired_buckets:
                                    pipe.mget([settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_{}".format(tcontrol.name,d)) for d in expired_buckets])
                                    pipe.expire(key,math.ceil(tcontrol.est_processtime / 1000) + 5)
                                    fetchtime,requests,expiredbuckets_requests,_ = pipe.execute()
                                else:
                                    pipe.expire(key,math.ceil(tcontrol.est_processtime / 1000) + 5)
                                    fetchtime,requests,_ = pipe.execute()
                                currentbucket[1] = True
                            fetchtime = timezone.make_aware(datetime.fromtimestamp(int(fetchtime[0]) + int(fetchtime[1]) / 1000000))
        
                            if expired_buckets:
                                #do some adjustment in memory if necessary because of race condition
                                totalrequests = nonexpired_requests
                                for i in range(len(expiredbuckets_requests)):
                                    if totalrequests >= tcontrol.concurrency:
                                        #already exceed the concurrency, the requests of the bucket should be 0
                                        #the reason why it is greater than 0 is the time gap between increment operation and decrement operation
                                        #adjust the requests to 0 in memory
                                        expiredbuckets_requests[i] = 0
                                        totalrequests += expiredbuckets_requests[i]
                                    else:
                                        expiredbuckets_requests[i] = int(expiredbuckets_requests[i]) if expiredbuckets_requests[i] else 0
                                        totalrequests += expiredbuckets_requests[i]
                                        if totalrequests > tcontrol.concurrency:
                                            #exceed the concurrency. caused by time gap between increment operation and decrement operation.
                                            #adjust the requests
                                            expiredbuckets_requests[i] -= totalrequests - tcontrol.concurrency
                                            totalrequests = tcontrol.concurrency

                                totalrequests += requests
                            else:
                                totalrequests = requests + nonexpired_requests
        
                        if totalrequests <= tcontrol.concurrency:
                            #not exceed the limit
                            #begin for debug
                            previous_bucketsstatus = _bucketsstatus("Previous")
                            #end for debug
                            succeed = True
                            if expired_buckets:
                                tcontrol.set_buckets(warnings,buckettime,bucketid,requests,fetchtime,expiredbuckets_requests)
                            else:
                                tcontrol.set_buckets(warnings,buckettime,bucketid,requests,fetchtime)
                            #begin for debug
                            _debug("After set_buckets{7}: buckets_endtime={0} , buckets_endid={1} , expired_buckets={2}, nonexpired bucket requests={3} , bucket requests={4} , expired bucket requests={5} , fetchtime={6}".format(buckettime.strftime("%Y-%m-%d %H:%M:%S.%f"),bucketid,expired_buckets or None,nonexpired_requests,requests,expiredbuckets_requests,fetchtime.strftime("%Y-%m-%d %H:%M:%S.%f"),"(Ignored)" if tcontrol._buckets_fetchtime and fetchtime < tcontrol._buckets_fetchtime else ""),previous_bucketsstatus)
                            #end for debug
                        else:
                            #if exceed the limit, can't access
                            if _log_tcontrol(cacheclient,settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_debuglog".format(tcontrol.name)),300):
                                #the log interval is 5 minutes
                                DebugLog.tcontrol(DebugLog.CONCURRENCY_TRAFFIC_CONTROL,tcontrol.name,clientip,client,"Exceed the limit({}); Now Have {} running requests".format(tcontrol.concurrency,totalrequests))

                            if buckettime:
                                #decrease the concurrency which was added before
                                #begin for debug
                                previous_bucketsstatus = _bucketsstatus("Previous")
                                #end for debug
                                redisrequests = requests
                                requests -= totalrequests - tcontrol.concurrency
                                if expired_buckets:
                                    tcontrol.set_buckets(warnings,buckettime,bucketid,requests,fetchtime,expiredbuckets_requests)
                                else:
                                    tcontrol.set_buckets(warnings,buckettime,bucketid,requests,fetchtime)
                                #begin for debug
                                _debug("After set_buckets{7}: buckets_endtime={0} , buckets_endid={1} , expired_buckets={2}, nonexpired bucket requests={3} , bucket requests={4} ,requests from redis={8} , expired bucket requests={5} , fetchtime={6}".format(buckettime.strftime("%Y-%m-%d %H:%M:%S.%f"),bucketid,expired_buckets or None,nonexpired_requests,requests,expiredbuckets_requests,fetchtime.strftime("%Y-%m-%d %H:%M:%S.%f"),"(Ignored)" if tcontrol._buckets_fetchtime and fetchtime < tcontrol._buckets_fetchtime else "",redisrequests),previous_bucketsstatus)
                                #end for debug

                                try:
                                    cacheclient.decr(key)
                                except:
                                    pass

       
                            if tcontrol.block or exempt:
                                #in block mode
                
                                #begin for debug
                                previous_bucketsstatus = _bucketsstatus("Previous")
                                #end for debug
                                checkingbuckets = tcontrol.get_checkingbuckets(warnings,today,milliseconds,exempt)
                            else:
                                #not in block mode
                                #decrease the user limit which was added before
                                if userlimitkey:
                                    try:
                                        usercacheclient.decr(userlimitkey)
                                    except:
                                        pass
                                #decrease the ip limit which was added before
                                if iplimitkey:
                                    try:
                                        ipcacheclient.decr(iplimitkey)
                                    except:
                                        pass
                                return [False,"CONCURRENCY",totalrequests]
    
                    if not checkingbuckets[0]:
                        #exceed the concurrency, booking a position in the future
                        result = False
                        pipe = pipe or cacheclient.pipeline()
                        while not result:
                            #exceed the concurrency, booking a position in the future
                            _,buckettime,bucketid,checkingbuckets_begintime,checkingbuckets_endtime,checkingbuckets_beginid,checkingbucketids = checkingbuckets
                            #begin for debug
                            _debug("After get_bookingbuckets.buckettime={} , bucketid={} , bookingbukcets_begintime={} , bookingbukcets_begintime={} , bookingbuckets_beginid={} , bookingbucketids={}".format(buckettime.strftime("%Y-%m-%d %H:%M:%S.%f"),bucketid,checkingbuckets_begintime.strftime("%Y-%m-%d %H:%M:%S.%f"),checkingbuckets_endtime.strftime("%Y-%m-%d %H:%M:%S.%f"),checkingbuckets_beginid,checkingbucketids),previous_bucketsstatus)
                            #end for debug
                            checkingbucketids = [d for d in checkingbucketids]
                            pipe.time() 
                            pipe.mget([settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_{}".format(tcontrol.name,d)) for d in checkingbucketids])
                            fetchtime,bucketsrequests = pipe.execute()
                            fetchtime = timezone.make_aware(datetime.fromtimestamp(int(fetchtime[0]) + int(fetchtime[1]) / 1000000))
                            for i in range(len(bucketsrequests)):
                                bucketsrequests[i] = int(bucketsrequests[i]) if bucketsrequests[i] else 0
                            #begin for debug
                            previous_bucketsstatus = _bucketsstatus("Previous")
                            #end for debug
                            result = tcontrol.set_bookedbuckets(warnings,buckettime,checkingbuckets_begintime,checkingbuckets_endtime,checkingbuckets_beginid,checkingbucketids,bucketsrequests,fetchtime)
                            #begin for debug
                            _debug("After set_bookedbuckets, {7} , buckets_endtime={0} , checkingbuckets begintime={1} , checkingbuckets endtime={2} , checkingbuckets beginid={3} , checkingbucket ids={4}, checkingbuckets requests={5} , fetchtime={6}".format(buckettime.strftime("%Y-%m-%d %H:%M:%S.%f"),checkingbuckets_begintime.strftime("%Y-%m-%d %H:%M:%S.%f"),checkingbuckets_endtime.strftime("%Y-%m-%d %H:%M:%S.%f"),checkingbuckets_beginid,checkingbucketids,bucketsrequests,fetchtime.strftime("%Y-%m-%d %H:%M:%S.%f"),"Try to book the running spot from the endbucket" if result else "Already reach the limit, fetch the requests of furture buckets again."),previous_bucketsstatus)
                            #end for debug
                            if not result:
                                #begin for debug
                                previous_bucketsstatus = _bucketsstatus("Previous")
                                #end for debug
                                if warnings:
                                    #save the warnings first
                                    for warning in warnings:
                                        warning.save()
                                    warning.clear()
                                checkingbuckets = tcontrol.get_checkingbuckets(warnings,today,milliseconds,exempt)
                                if checkingbuckets[0]:
                                    #not a future booking, retry the concurrency logic again
                                    break

                        if not result:
                            #not a future booking, retry the concurrency logic again
                            break
    
                        #start to book the position from end bucket
                        while not succeed:
                            totalrequests = tcontrol._buckets_totalrequests - tcontrol._buckets[-1]
                            bucketid = tcontrol._buckets_endid
                            buckettime = tcontrol._buckets_endtime
                            waitingtime = (buckettime - timezone.localtime()).total_seconds()
                            if waitingtime> tcontrol.bookingtimeout:
                                #begin for debug
                                _debug("Booking timeout. the time({2}) between booking time({1}) and now is greater than timeout({0})".format(tcontrol.bookingtimeout,buckettime.strftime("%Y-%m-%d %H:%M:%S.%f"),(buckettime - timezone.localtime()).total_seconds()),_bucketsstatus("Previous"))
                                #end for debug
                                return [False,"CONCURRENCY","TIMEOUT",waitingtime]
                            key = settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_{}".format(tcontrol.name,bucketid))
                            currentbucket = _currentbuckets.get(tcontrol.id)
                            if not currentbucket:
                                currentbucket = [buckettime,False]
                                _currentbuckets[tcontrol.id] = currentbucket
                            elif currentbucket[0] != buckettime:
                                currentbucket[0] = buckettime
                                currentbucket[1] = False
                            if currentbucket[1]:
                                requests = cacheclient.incr(key)
                            else:
                                pipe = cacheclient.pipeline()
                                pipe.incr(key)
                                pipe.expire(key,math.ceil(tcontrol.est_processtime / 1000) + 5 + math.ceil((buckettime - timezone.localtime()).total_seconds()))
                                requests,_ = pipe.execute()

                            if totalrequests + requests > tcontrol.concurrency:
                                #exceed the limit,decrease the requests and adjust the requests
                                redisrequests = requests
                                requests =  tcontrol.concurrency - totalrequests
                                #begin for debug
                                previous_bucketsstatus = _bucketsstatus("Previous")
                                #end for debug
                                try:
                                    setted = tcontrol.set_bookingbucket(warnings,buckettime,bucketid,requests,(totalrequests + redisrequests))

                                    #begin for debug
                                    _debug("After set_bookingbucket{4}, Failed to book the spot in the bucket.bookingbuckets endtime={0} , bookingbuckets endid={1} , bucket requests={2}, redis requests={5} , total requests={3}".format(buckettime.strftime("%Y-%m-%d %H:%M:%S.%f"),bucketid,requests,totalrequests + requests,"{Ignored}" if not setted else "",redisrequests),previous_bucketsstatus)
                                    #end for debug
                                    cacheclient.decr(key)
                                    continue
                                except Exception as ex:
                                    #begin for debug
                                    _debug("After set_bookingbucket{4}, Failed to book the spot in the bucket.bookingbuckets endtime={0} , bookingbuckets endid={1} , bucket requests={2}, redis requests={5} , total requests={3} , msg={6}".format(buckettime.strftime("%Y-%m-%d %H:%M:%S.%f"),bucketid,requests,totalrequests + requests,"{Ignored}" if not setted else "",redisrequests,msg),previous_bucketsstatus)
                                    #end for debug
                                    cacheclient.decr(key)
                            else:
                                #begin for debug
                                previous_bucketsstatus = _bucketsstatus("Previous")
                                #end for debug
                                try:
                                    setted = tcontrol.set_bookingbucket(warnings,buckettime,bucketid,requests,(totalrequests + requests))
                                except Exception as ex:
                                    #begin for debug
                                    _debug("After set_bookingbucket{4}, Failed to book the spot in the bucket.bookingbuckets endtime={0} , bookingbuckets endid={1} , bucket requests={2}, redis requests={5} , total requests={3} , msg={6}".format(buckettime.strftime("%Y-%m-%d %H:%M:%S.%f"),bucketid,requests,totalrequests + requests,"{Ignored}" if not setted else "",redisrequests,msg),previous_bucketsstatus)
                                    #end for debug
                                    cacheclient.decr(key)
                                    raise ex

                                #begin for debug
                                _debug("After set_bookingbucket{4}, Succeed to book the spot in the bucket.bucket begintime={0} , bucketid={1} , bucket requests={2}, total requests={3}".format(buckettime.strftime("%Y-%m-%d %H:%M:%S.%f"),bucketid,requests,totalrequests + requests,"{Ignored}" if not setted else ""),previous_bucketsstatus)
                                #end for debug

                                waittime = (buckettime - timezone.localtime()).total_seconds()
                                if waittime > 0:
                                    times = int(waittime * 1000 / tcontrol.est_processtime)
                                    if times > 0:
                                        if _log_tcontrol(cacheclient,settings.GET_TRAFFICCONTROL_CACHE_KEY("{}_debuglog_{}times".format(tcontrol.name,times)),300):
                                            #the log interval is 5 minutes
                                            DebugLog.tcontrol(DebugLog.CONCURRENCY_TRAFFIC_CONTROL,tcontrol.name,clientip,client,"Have at least {0} requests waiting in the queue;".format(tcontrol.concurrency * times))
                                    if not test:
                                        time.sleep(waittime)
                                totalrequests += requests
                                succeed = True
                                bookingtime = buckettime

            except Exception as ex:
                traceback.print_exc()
                exception = ex
    
        #not exceed any traffic control, allow access
        if exception:
            return [True,str(exception)]
        elif test:
            data = {}
            if userrequests:
                data["user_requests"] = userrequests
            if iprequests:
                data["ip_requests"] = iprequests
            if totalrequests:
                data["totalrequests"] = totalrequests
            if bookingtime:
                data["bookingtime"] = bookingtime.strftime("%Y-%m-%d %H:%M:%S.%f") if bookingtime else None
            return [True,data]
        elif booking:
            return [True,bookingtime.strftime("%Y-%m-%d %H:%M:%S.%f") if bookingtime else None]
        else:
            return [True,None]
    except Exception as ex:
        #record the error every 5 minutes
        traceback.print_exc()
        msg = "{}:{}".format(ex.__class__.__name__,str(ex))
        if settings.CACHE_KEY_PREFIX:
            errorkey = "{}:auth2_tcontrol_error_{}".format(settings.CACHE_KEY_PREFIX,hash(msg))
        else:
            errorkey = "auth2_tcontrol_error_{}".format(hash(msg))

        defaultcacheclient = defaultcache.redis_client
        if _log_tcontrol(defaultcacheclient,settings.GET_TRAFFICCONTROL_CACHE_KEY(errorkey),300):
            DebugLog.tcontrol(DebugLog.TRAFFIC_CONTROL_ERROR,tcontrol.name,clientip,client,msg)

        #check failed, ignore traffic control
        return [True,str(ex)]
    finally:
        if warnings:
            for warning in warnings:
                warning.save()
            
def _tcontrol(request):
    clientip = request.headers.get("x-real-ip")

    domain = request.get_host()
    path = request.headers.get("x-upstream-request-uri")
    if path:
        #get the original request path
        #remove the query string
        try:
            path = path[:path.index("?")]
        except:
            pass
    else:
        #can't get the original path, use request path directly
        path = request.path

    method = request.headers.get("x-upstream-request-method") or "GET"
    if not method:
        method = models.TrafficControlLocation.GET
    else:
        method = models.TrafficControlLocation.METHODS.get(method) or models.TrafficControlLocation.METHODS.get(method.upper()) or models.TrafficControlLocation.GET

    tcontrol = cache.tcontrols.get((domain,path,method))
    if not tcontrol or not tcontrol.active:
        #no traffic control policies are enabled.
        return None
    exempt = False
    if request.user.is_authenticated:
        client = request.user.email
        if tcontrol.is_exempt(client):
            #is the user we known,exempt traffic control
            if (tcontrol.iplimit == 0 or tcontrol.iplimitperiod == 0) and (tcontrol.concurrency == 0 or tcontrol.est_processtime == 0):
                return None
            else:
                exempt = True
    elif settings.TRAFFICCONTROL_COOKIE_NAME:
        client = request.COOKIES.get(settings.TRAFFICCONTROL_COOKIE_NAME) or None
    else:
        client = None

    if settings.TRAFFICCONTROL_SUPPORTED:
        result = _check_tcontrol(tcontrol,clientip,client,exempt)
    else:
        result = cahce.tcontrol(settings.TRAFFICCONTROL_CLUSTERID,tcontrol.id,clientip,client,exempt)
    
    if result[0]:
        return None
    else:
        res = HttpResponseForbidden("Denied")
        res["x-tcontrol"] = urllib.parse.quote("{1}|{0}|{2}".format(tcontrol.id,result[1],result[2]) if len(result) < 4  else "{1}|{0}|{2}|{3}".format(tcontrol.id,result[1],result[2],result[3]))
        return res

def auth_tcontrol(request):
    res = auth(request)
    if res.status_code > 300:
        return res
    #authentication and authorization succeed
    #check the traffic control
    return _tcontrol(request) or res

def auth_optional_tcontrol(request):
    res = auth_optional(request)
    if res.status_code > 300:
        return res
    #check the traffic control
    return _tcontrol(request) or res

def auth_basic_tcontrol(request):
    res = auth_basic(request)
    if res.status_code > 300:
        return res
    #check the traffic control
    return _tcontrol(request) or res

def auth_basic_optional_tcontrol(request):
    res = auth_basic_optional(request)
    if res.status_code > 300:
        return res
    #check the traffic control
    return _tcontrol(request) or res
