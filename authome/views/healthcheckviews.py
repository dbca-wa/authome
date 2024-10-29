import os

from django.conf import settings
from django.http import HttpResponse,FileResponse
from django.shortcuts import render
from django.template.response import TemplateResponse
from django.utils.html import mark_safe

from ..cache import cache
from ..response import MultiFileSegmentsResponse

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

auth2_status = _auth2_cluster_status if settings.AUTH2_CLUSTER_ENABLED else _auth2_status
auth2_liveness = _auth2_cluster_liveness if settings.AUTH2_CLUSTER_ENABLED else _auth2_liveness
