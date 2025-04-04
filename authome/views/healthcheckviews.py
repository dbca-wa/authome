import os
import re

from datetime import timedelta,datetime

from django.conf import settings
from django.http import HttpResponse,FileResponse,JsonResponse
from django.utils import timezone
from django.shortcuts import render
from django.template.response import TemplateResponse
from django.utils.html import mark_safe

from ..cache import cache
from ..response import MultiFileSegmentsResponse
from ..serializers import JSONEncoder
from .. import utils

def _auth2_cluster_status(request,clusterid):
    if clusterid == "standalone" or clusterid == settings.AUTH2_CLUSTERID:
        p = os.path.join(settings.AUTH2_MONITORING_DIR,"auth2",clusterid)
        servers = []
        if os.path.exists(p):
            for server in os.listdir(p):
                serverpath = os.path.join(p,server)
                if os.path.isdir(serverpath):
                    filepath = os.path.join(serverpath,"serverinfo.html")
                    readyfilepath = os.path.join(serverpath,"latestreadytime")
                    if os.path.exists(filepath):
                        with open(filepath,'r') as f:
                            if os.path.exists(readyfilepath):
                                try:
                                    with open(readyfilepath,'r') as f2:
                                        servers.append((f.read(),int(f2.read().strip())))
                                except:
                                    servers.append((f.read(),0))
                            else:
                                servers.append((f.read(),0))

        if servers:
            servers.sort(key=lambda d:d[1],reverse=True)
            data = "\n".join([s[0] for s in servers])
            context = {"data":mark_safe(data),"clusterid":clusterid}
            if clusterid == "standalone":
                context["title"] = "Auth2 Server Status"
            else:
                context["title"] = "Auth2 Cluster Server({}) Status".format(clusterid)
            return TemplateResponse(request,"authome/auth2serverstatus.html",context=context)
        else:
            return TemplateResponse(request,"authome/healthcheck_not_enabled.html",context={"message":"The healthcheck is not enabled for auth2 cluster({})".format(clusterid)})
    else:
        return HttpResponse(cache.get_auth2_status(clusterid),content_type="text/html")
    

def _auth2_status(request):
    return _auth2_cluster_status(request,"standalone")

def _auth2_cluster_liveness(request,clusterid,serviceid,monitordate):
    if clusterid == "standalone" or clusterid == settings.AUTH2_CLUSTERID:
        f = os.path.join(settings.AUTH2_MONITORING_DIR,"auth2",clusterid,serviceid,"liveness","{}.html".format(monitordate))
        if os.path.exists(f):
            return MultiFileSegmentsResponse([f,os.path.join(settings.AUTH2_MONITORING_DIR,"auth2",clusterid,serviceid,"livenessfooter.html")],filename="{}-{}-{}.html".format(clusterid,serviceid,monitordate))
        else:
            return TemplateResponse(request,"authome/livenessfile_missing.html",context={"message":"The liveness file({}) does not exist".format(f)})
    else:
        return HttpResponse(cache.get_auth2_liveness(clusterid,serviceid,monitordate),content_type="text/html")

def _auth2_liveness(request,serviceid,monitordate):
    return _auth2_cluster_liveness(request,"standalone",serviceid,monitordate)

serverinfo_re = re.compile("['\"](?P<serverid>[a-zA-Z0-9_\\-\\.:]+)readytime['\"][^a-zA-Z0-9_\\-\\.]+(?P<readytime>[0-9][0-9\\- :]*[0-9])?.+['\"](?P=serverid)heartbeat['\"][^a-zA-Z0-9_\\-\\.]+(?P<heartbeat>[0-9][0-9\\- :]*[0-9])?",re.DOTALL)
def _auth2_local_onlinestatus():
    clusterid = settings.AUTH2_CLUSTERID if settings.AUTH2_CLUSTER_ENABLED else "standalone"
    p = os.path.join(settings.AUTH2_MONITORING_DIR,"auth2",clusterid)
    servers = [[],[]]
    if os.path.exists(p):
        for server in os.listdir(p):
            serverpath = os.path.join(p,server)
            if os.path.isdir(serverpath):
                filepath = os.path.join(serverpath,"serverinfo.html")
                if os.path.exists(filepath):
                    with open(filepath,'r') as f:
                        serverinfo = f.read()
                    m = serverinfo_re.search(serverinfo)
                    if m :
                        readytime = timezone.make_aware(datetime.strptime(m.group("readytime"),"%Y-%m-%d %H:%M:%S")) if m.group("readytime") else None
                        heartbeat = timezone.make_aware(datetime.strptime(m.group("heartbeat"),"%Y-%m-%d %H:%M:%S")) if m.group("heartbeat") else None
                        serverid = m.group("serverid")
                        if readytime and heartbeat:
                            servers[0].append([readytime,heartbeat,serverid])
                        else:
                            servers[1].append([heartbeat or readytime,serverid])

    servers[0].sort()
    servers[1].sort()


    return servers

def auth2_local_onlinestatus(request):
    return JsonResponse({"onlinestatus":_auth2_local_onlinestatus()},status=200,encoder=JSONEncoder)

def _populate_onlinestatus(serverstatuslist,now,earliestMonitorDay,monitortime4Now):
    #if the latest heartbeat is later than now - 15 seconds, set the latest heartbeat to now
    for server in serverstatuslist:
        if server[1] >= monitortime4Now:
            server[1] = now
        #truncate the microsecond
        server[0] = server[0].replace(microsecond=0)
        server[1] = server[1].replace(microsecond=0)
        #append an element to serverstatus to set the endtime.
        server.append(None)

    #remove the online status before earliestMonitorDay
    index = 0
    while (index < len(serverstatuslist)) and (serverstatuslist[index][0] < earliestMonitorDay):
        if serverstatuslist[index][1] < earliestMonitorDay:
            del serverstatuslist[index]
        else:
            index += 1

    #add an end element to serverstatuslist
    serverstatuslist.append(None)

    onlinestatuslist = []
    online_begintime = earliestMonitorDay
    while serverstatuslist:
        online_endtime = None
        serverindex = -1
        online_status = [online_begintime,None,[]]
        for index in range(len(serverstatuslist)):
            server = serverstatuslist[index]
            if server == None:
                #no more auth2 servers
                if not online_endtime:
                    #can't find any server whose readytime is before online_begintime
                    if online_begintime < now:
                        #the last heartbeat was happend before, auth2 is offline
                        online_status[1] = now
                        onlinestatuslist.append(online_status)
                    #delete the end element to jump out the loop, the index should be 0
                    del serverstatuslist[index]
                else:
                    if online_status[0] == online_endtime:
                        #the online_status is same as the last online status in the onlinestauslist. ignore the current online_status
                        pass
                    else:
                        online_status[1] = online_endtime
                        onlinestatuslist.append(online_status)

                    serverstatuslist[serverindex][-1] = online_endtime
                    del serverstatuslist[serverindex]
                    online_begintime = online_endtime
                break
            elif server[0] <= online_begintime:
                #the server was online at time 'online_begintime', add the server to the online server list
                online_status[2].append(server)
                if not online_endtime or online_endtime > server[1]:
                    #this server was terminated before other online servers. assign the terminate time as online_endtime
                    online_endtime = server[1]
                    serverindex = index
            else:
                #the current server was not online at time 'online_begintime'
                if not online_endtime:
                    #auth2 was offline between online_begintime and this server's ready time
                    online_status[1] = server[0]
                    onlinestatuslist.append(online_status)
                    online_begintime = server[0]
                elif server[0] <= online_endtime:
                    #the current server was ready before the earliest terminate time of the online server list
                    #A new server was created or an old server would be replaced.
                    if online_status[0] == server[0]:
                        #the online_status is same as the last online status in the onlinestauslist. ignore the current online_status
                        pass
                    else:
                        online_status[1] = server[0]
                        onlinestatuslist.append(online_status)
                        
                    if (online_endtime != now) and (online_endtime - server[0]).total_seconds() < 120:
                        #an old server was replaced, delete the old server.
                        serverstatuslist[serverindex][-1] = server[0]
                        del serverstatuslist[serverindex]
                    #use the current server's ready time as online_begintime
                    online_begintime = server[0]
                else:
                    #the current server's ready time was after the earliest terminate time of the online server list
                    #the server with the earliest terminate time was shutdown without replacement.
                    if online_status[0] == online_endtime:
                        #the online_status is same as the last online status in the onlinestauslist. ignore the current online_status
                        pass
                    else:
                        online_status[1] = online_endtime
                        onlinestatuslist.append(online_status)
                 
                    #use the current server's ready time as online_begintime
                    online_begintime = online_endtime
                    #delete the server with the earliest terminate time because it was shutdown before "online_begintime"
                    serverstatuslist[serverindex][-1] = online_endtime
                    del serverstatuslist[serverindex]
                #this current server is the first server whose readytime is later than online_begintime. stop processing.
                break
    return onlinestatuslist


def auth2_onlinestatus(request):
    now = timezone.localtime().replace(microsecond=0)
    today = now.replace(hour=0,minute=0,second=0,microsecond=0)
    earliestMonitorDay = today - timedelta(days=settings.AUTH2_MONITOR_EXPIREDAYS)
    monitortime4Now = now - timedelta(seconds=30)
    
    allservers = _auth2_local_onlinestatus()
    onlinestatuslist = _populate_onlinestatus(allservers[0],now,earliestMonitorDay,monitortime4Now)
    failedserverlist = allservers[1]

    #get hte servers from other cluster
    if settings.AUTH2_CLUSTER_ENABLED and len(cache.auth2_clusters) > 0:
        for onlinestatus in onlinestatuslist:
            for server in onlinestatus[2]:
                 server[2] = "{}.{}".format(settings.AUTH2_CLUSTERID,server[2])
        for failedserver in failedserverlist:
            failedserver[1] = "{}.{}".format(settings.AUTH2_CLUSTERID,failedserver[1])

        clusteronlinestatuslist = [onlinestatuslist]

        for clusterid  in cache.auth2_clusters.keys():
            allservers = cache.get_auth2_onlinestatus(clusterid)["onlinestatus"]
            onlinestatuslist = _populate_onlinestatus(allservers[0],now,earliestMonitorDay,monitortime4Now)
            for onlinestatus in onlinestatuslist:
                 for server in onlinestatus[2]:
                     server[2] = "{}.{}".format(settings.AUTH2_CLUSTERID,server[2])
            clusteronlinestatuslist.append(onlinestatuslist)

            for failedserver in allservers[1]:
                failedserver[1] = "{}.{}".format(clusterid,failedserver[1])
            failedserverlist.extend(allservers[1])

        failedserverlist.sort()

        length = len(clusteronlinestatuslist)
        indexlist = [0] * length
        
        onlinestatuslist = []
        onlinestatus = [earliestMonitorDay,None,[]]
        poslist = []
        while any(indexlist[pos] < len(clusteronlinestatuslist[pos]) for pos in range(length)):
            #find the online_endtime and populate the serverlist
            for pos in range(length):
                print("{}: pos={}, index={},length={}".format(onlinestatus[:2],pos,indexlist[pos],len(clusteronlinestatuslist[pos])))
                clusteronlinestatus = clusteronlinestatuslist[pos][indexlist[pos]]
                if clusteronlinestatus[0] <= onlinestatus[0]:
                    #this clusteronlinestatus includes the time "oneline_begintime"
                    if not onlinestatus[1]:
                        #this is the first clusteronlinestatus at time "onlinestatus[0]"
                        poslist.clear()
                        poslist.append(pos)
                        onlinestatus[1] = clusteronlinestatus[1]
                        if clusteronlinestatus[2]:
                            onlinestatus[2].extend(clusteronlinestatus[2])
                    elif onlinestatus[1] < clusteronlinestatus[1]:
                        #this clusteronlinestatus has longer lifetime
                        if clusteronlinestatus[2]:
                            onlinestatus[2].extend(clusteronlinestatus[2])
                    elif onlinestatus[1] == clusteronlinestatus[1]:
                        #this clusteronlinestatus has the same lifetime
                        poslist.append(pos)
                        if clusteronlinestatus[2]:
                            onlinestatus[2].extend(clusteronlinestatus[2])
                    else:
                        #this clusteronlinestatus has shorter lifetime
                        poslist.clear()
                        poslist.append(pos)
                        onlinestatus[1] = clusteronlinestatus[1]
                        if clusteronlinestatus[2]:
                            onlinestatus[2].extend(clusteronlinestatus[2])
            
            onlinestatuslist.append(onlinestatus)
            #advance the indexlist
            for pos in poslist:
                indexlist[pos] += 1
            print("***={}".format(onlinestatus[:2]))
            onlinestatus = [onlinestatus[1],None,[]]

    #format the datetime
    for server in onlinestatuslist:
        server[0] = utils.format_datetime(server[0])
        if server[1] == now:
            server[1] = "NOW"
        else:
            server[1] = utils.format_datetime(server[1])

        for index in range(len(server[2])):
            if isinstance(server[2][index][0],datetime):
                server[2][index][0] = utils.format_datetime(server[2][index][0])
            if server[2][index][3] and isinstance(server[2][index][3],datetime):
                server[2][index][3] = utils.format_datetime(server[2][index][3])
            if isinstance(server[2][index][1],datetime):
                if server[2][index][1] == now:
                    server[2][index][1] = "NOW"
                else:
                    server[2][index][1] = utils.format_datetime(server[2][index][1])

    for server in failedserverlist:
        if server[0]:
            server[0] = utils.format_datetime(server[0])

    return TemplateResponse(request,"authome/auth2onlinestatus.html",context={"onlinestatuslist":onlinestatuslist,"failedserverlist":failedserverlist})
        


auth2_status = _auth2_cluster_status if settings.AUTH2_CLUSTER_ENABLED else _auth2_status
auth2_liveness = _auth2_cluster_liveness if settings.AUTH2_CLUSTER_ENABLED else _auth2_liveness
