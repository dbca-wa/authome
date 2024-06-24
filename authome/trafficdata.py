import logging
import requests
from datetime import datetime,timedelta
import itertools
import traceback

from django.conf  import settings
from django.utils import timezone
from django.db import transaction

from . import models
from . import utils
from .views.monitorviews import  _save_trafficdata,_sum,_add_avg

logger = logging.getLogger(__name__)

BATCHID_END = timezone.make_aware(datetime.fromtimestamp(0))
def save2db():
    logger.info("Begin to save traffic data from redis to database")
    #get a batchid
    batchid = utils.decode_datetime(utils.encode_datetime(timezone.localtime()))
    status_obj = models.TrafficDataProcessStatus.objects.all().order_by("-last_saved_batchid").first()
    if status_obj and status_obj.last_saved_batchid and status_obj.last_saved_batchid >= batchid:
        logger.warning("System's time is not configured properly.")
        batchid = status_obj.last_save_batchid + timedelta(seconds=1)

    try:
        if settings.AUTH2_CLUSTERID:
            _save_cluster_traffic_data(batchid)
        else:
            _save_traffic_data(batchid)
    except:
        logger.error("Failed to process traffic data.{}".format(traceback.format_exc()))

    _populate_reports()
    return batchid

def _save_cluster_traffic_data(batchid):
    clusters_process_status = []
    #get a batchid
    encoded_batchid = utils.encode_datetime(batchid)

    #save traffic data
    for cluster in models.Auth2Cluster.objects.all():
        status_obj = models.TrafficDataProcessStatus.objects.filter(cluster=cluster).first()
        if status_obj and status_obj.disabled:
            continue
        try:
            res = requests.get("{}/cluster/trafficdata/save?batchid={}".format(
                cluster.endpoint,
                encoded_batchid
            ),headers={"HOST":settings.AUTH2_DOMAIN},verify=settings.SSL_VERIFY)
            res.raise_for_status()
            data = res.json().get("result",[]) 
            if data:
                data.sort(key=lambda o:o[0]) 
                data = "\n    ".join("start_time={}, end_time={}, requests={}, get_remote_session={}, delete_remote_sessions={}".format(*d) for d in data)
                logger.info("Succeed to save the traffic data for cluster({}).batchid={}\n    {}".format(cluster.clusterid,batchid,data))
            else:
                logger.info("No new traffic data for cluster({}).batchid={}".format(cluster.clusterid,batchid))
                pass
        except Exception as ex:
            logger.error("Failed to save the traffic data for cluster({}).{}".format(cluster.clusterid,traceback.format_exc()))



def _save_traffic_data(batchid):
    try:
        data = _save_trafficdata(batchid)
        if data:
            data.sort(key=lambda o:o[0]) 
            data = "\n    ".join("start_time={}, end_time={}, requests={}, get_remote_session={}, delete_remote_sessions={}".format(*d) for d in data)
            logger.info("Succeed to save the traffic data .batchid={}\n    {}".format(batchid,data))
        else:
            logger.info("No new traffic data.batchid={}\n    {}".format(batchid))
            pass
    except:
        msg = "Failed to save the traffic data.{}".format(traceback.format_exc())
        logger.error(msg)
 
def _populate_reports():
    if settings.AUTH2_CLUSTERID:
        process_status_qs = models.TrafficDataProcessStatus.objects.filter(clusterid__isnull=False,disabled=False).exclude(clusterid="AUTH2")
    else:
        process_status_qs = models.TrafficDataProcessStatus.objects.filter(cluster__isnull=True,clusterid__isnull=True,disabled=False)

    #update the existing report if some delayer traffic data found
    traffic_reports = {}
    method_traffic_reports = {}
    for process_status in process_status_qs:
        if process_status.clusterid:
            data_qs = models.TrafficData.objects.filter(clusterid=process_status.clusterid).order_by("batchid")
        else:
            data_qs = models.TrafficData.objects.filter(clusterid__isnull=True).order_by("batchid")

        if process_status.last_processed_batchid:
            data_qs = data_qs.filter(batchid__gt=process_status.last_processed_batchid)


        processing_batchid = None
        #In order to save the last data, add a fake TrafficData at the end 
        for data in itertools.chain(data_qs,[models.TrafficData(batchid=BATCHID_END)]):

            if not processing_batchid:
                processing_batchid = data.batchid
            elif processing_batchid != data.batchid:
                #saving the data 
                with transaction.atomic():
                    #save changed report
                    for traffic_report in traffic_reports.values():
                        if traffic_report.changed:
                            traffic_report.save()
                            logger.info("{}Save the traffic report({}), requests={}".format("{}.".format(traffic_report.clusterid) if traffic_report.clusterid else "","{}({} - {})".format(models.TrafficReport.get_reportname(traffic_report.report_type),utils.format_datetime(traffic_report.start_time),utils.format_datetime(traffic_report.end_time)), traffic_report.requests))
                    for traffic_report in method_traffic_reports.values():
                        if traffic_report.changed:
                            traffic_report.save()
                    #save process status
                    process_status.last_processed_batchid = processing_batchid
                    process_status.save(update_fields=["last_processed_batchid"])

                processing_batchid = data.batchid
                #reset report change flag
                for traffic_report in traffic_reports.values():
                    traffic_report.changed = False

                for traffic_report in method_traffic_reports.values():
                    traffic_report.changed = False
                    

            if data.batchid == BATCHID_END:
                continue
            if not data.requests and not data.get_remote_sessions and not data.delete_remote_sessions:
                #no requests
                continue

            method_data_qs = models.SSOMethodTrafficData.objects.filter(traffic_data = data)

            for report_type,report_name,f_report_starttime,f_report_endtime in models.TrafficReport.REPORTS:
                report_starttime = f_report_starttime(data.start_time)
                report_endtime = f_report_endtime(data.start_time)
                if process_status.clusterid:
                    report_keys = [(process_status.cluster,process_status.clusterid,report_type,report_starttime),(None,"AUTH2",report_type,report_starttime)]
                else:
                    report_keys = [(None,None,report_type,report_starttime)]
                for report_key in report_keys:
                    logger.debug("{}Add the traffic data to traffic report({}). {}start_time={}, end_time={}, batchid= {}, requests={}".format("{} : ".format(report_key[1]) if report_key[1] else "","{}({} - {})".format(report_name,utils.format_datetime(report_starttime),utils.format_datetime(report_endtime)),"cluster={}, ".format(data.clusterid) if data.clusterid else "", utils.format_datetime(data.start_time),utils.format_datetime(data.end_time),utils.format_datetime(data.batchid),data.requests))
                    traffic_report = traffic_reports.get(report_key)
                    if not traffic_report:
                        traffic_report,created = models.TrafficReport.objects.get_or_create(
                            clusterid = report_key[1],
                            report_type = report_type,
                            start_time = report_starttime,
                            end_time = report_endtime,
                            defaults = {
                                "cluster" : report_key[0]
                            }
                        )
                        traffic_reports[report_key] = traffic_report

                    traffic_report.requests += data.requests or 0
                    if data.total_time:
                        if traffic_report.total_time:
                            traffic_report.total_time += data.total_time
                        else:
                            traffic_report.total_time = data.total_time 
                    if data.min_time:
                        if not traffic_report.min_time or traffic_report.min_time > data.min_time:
                            traffic_report.min_time = data.min_time
                    if data.max_time:
                        if not traffic_report.max_time or traffic_report.max_time < data.max_time:
                            traffic_report.max_time = data.max_time
                    if traffic_report.requests:
                        traffic_report.avg_time = (traffic_report.total_time or 0) / traffic_report.requests
                    traffic_report.get_remote_sessions += data.get_remote_sessions or 0
                    traffic_report.delete_remote_sessions += data.delete_remote_sessions or 0

                    if data.status:
                        if traffic_report.status:
                            _sum(traffic_report.status,data.status)
                        else:
                            traffic_report.status = data.status

                    if data.domains:
                        if traffic_report.domains:
                            _sum(traffic_report.domains,data.domains)
                            _add_avg(traffic_report.domains)
                        else:
                            traffic_report.domains = data.domains

                    traffic_report.changed = True

                for method_data in method_data_qs:
                    method_report_keys = [(key,method_data.sso_method) for key in report_keys]

                    for method_report_key in method_report_keys:
                        method_traffic_report = method_traffic_reports.get(method_report_key)
                        if not method_traffic_report:
                            method_traffic_report,created = models.SSOMethodTrafficReport.objects.get_or_create(
                                report = traffic_reports[method_report_key[0]],
                                sso_method = method_data.sso_method
                            )
                            method_traffic_reports[method_report_key] = method_traffic_report

                        method_traffic_report.requests += method_data.requests or 0
                        if method_data.total_time:
                            if method_traffic_report.total_time:
                                method_traffic_report.total_time += method_data.total_time
                            else:
                                method_traffic_report.total_time = method_data.total_time 
                        if method_data.min_time:
                            if not method_traffic_report.min_time or method_traffic_report.min_time > method_data.min_time:
                                method_traffic_report.min_time = method_data.min_time
                        if method_data.max_time:
                            if not method_traffic_report.max_time or method_traffic_report.max_time < method_data.max_time:
                                method_traffic_report.max_time = method_data.max_time
                        if method_traffic_report.requests:
                            method_traffic_report.avg_time = (method_traffic_report.total_time or 0) / method_traffic_report.requests

                        if method_data.status:
                            if method_traffic_report.status:
                                _sum(method_traffic_report.status,method_data.status)
                            else:
                                method_traffic_report.status = method_data.status

                        if method_data.domains:
                            if method_traffic_report.domains:
                                _sum(method_traffic_report.domains,method_data.domains)
                                _add_avg(method_traffic_report.domains)
                            else:
                                method_traffic_report.domains = method_data.domains
    
                        method_traffic_report.changed = True
    if not traffic_reports :
        logger.info("No new traffic data and all traffic reports are latest.")
