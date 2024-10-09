import os

from django.conf import settings
from django.http import HttpResponse,FileResponse
from django.shortcuts import render
from django.template.response import TemplateResponse

from ..cache import cache

def _auth2_cluster_status(request,clusterid):
    if clusterid == settings.AUTH2_CLUSTERID:
        f = os.path.join(settings.AUTH2_MONITORING_DIR,"auth2",clusterid,"serverinfo.html")
        if os.path.exists(f):
            return FileResponse(open(f,'rb'))
        else:
            return TemplateResponse(request,"authome/healthcheck_not_enabled.html",context={"message":"The healthcheck is not enabled for auth2 cluster({})".format(clusterid)})
    else:
        return HttpResponse(cache.get_auth2_status(clusterid),content_type="text/html")
    

def _auth2_status(request):
    f = os.path.join(settings.AUTH2_MONITORING_DIR,"auth2","standalone","serverinfo.html")
    if os.path.exists(f):
        return FileResponse(open(f,'rb'))
    else:
        return TemplateResponse(request,"authome/healthcheck_not_enabled.html",context={"message":"The healthcheck is not enabled for auth2 server"})

def _auth2_cluster_liveness(request,clusterid,serviceid,monitordate):
    if clusterid == settings.AUTH2_CLUSTERID:
        return FileResponse(open(os.path.join(settings.AUTH2_MONITORING_DIR,"auth2",clusterid,serviceid,"{}.html".format(monitordate)),'rb'))
    else:
        return HttpResponse(cache.get_auth2_liveness(clusterid,serviceid,monitordate),content_type="text/html")

def _auth2_liveness(request,serviceid,monitordate):
    return FileResponse(open(os.path.join(settings.AUTH2_MONITORING_DIR,"auth2","standalone",serviceid,"{}.html".format(monitordate)),'rb'))

auth2_status = _auth2_cluster_status if settings.AUTH2_CLUSTER_ENABLED else _auth2_status
auth2_liveness = _auth2_cluster_liveness if settings.AUTH2_CLUSTER_ENABLED else _auth2_liveness
