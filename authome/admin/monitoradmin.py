import  json
import logging

from django.contrib import admin as djangoadmin
from django.utils.html import mark_safe
from django.urls import reverse
from django.conf import settings

from . import admin
from .. import  models

logger = logging.getLogger(__name__)

class TrafficDataPropertyMixin(object):
    def _cluster(self,obj):
        if not obj or (not obj.cluster and not obj.clusterid):
            return ""
        else:
            return obj.cluster.clusterid if obj.cluster else obj.clusterid
    _cluster.short_description = "Cluster"

    def _total_time(self,obj):
        if not obj or not obj.total_time:
            return ""
        else:
            return round(obj.total_time,2)
    _total_time.short_description = "Total Time"

    def _min_time(self,obj):
        if not obj or not obj.min_time:
            return ""
        else:
            return round(obj.min_time,2)
    _min_time.short_description = "Min Time"

    def _max_time(self,obj):
        if not obj or not obj.max_time:
            return ""
        else:
            return round(obj.max_time,2)
    _max_time.short_description = "Max Time"

    def _avg_time(self,obj):
        if not obj or not obj.avg_time:
            return ""
        else:
            return round(obj.avg_time,2)
    _avg_time.short_description = "Avg Time"

    def _domains(self,obj):
        if not obj or not obj.domains:
            return ""
        else:
            datas = [(k,v) for k,v in obj.domains.items()]
            datas.sort(key=lambda o:((o[1].get("requests") or 0) * -1,o[0]) if isinstance(o[1],dict) else (o[1] * -1,o[0]))
            return mark_safe("<pre>{}</pre>".format("\r\n".join("  {} : {}".format(o[0],json.dumps(o[1],sort_keys=True,indent=4) if isinstance(o[1],dict) else o[1]) for o in datas)))
    _domains.short_description = "Domains"

    def _status(self,obj):
        if not obj or not obj.status:
            return ""
        else:
            datas = [(k,v) for k,v in obj.status.items()]
            datas.sort(key=lambda o:o[0])
            return mark_safe("<pre>{}</pre>".format("\r\n".join("  {} : {}".format(o[0],o[1]) for o in datas)))
    _status.short_description = "Status"


class SSOMethodTrafficDataInline(TrafficDataPropertyMixin,djangoadmin.TabularInline):
    model = models.SSOMethodTrafficData
    readonly_fields = ("sso_method","requests","_total_time","_min_time","_max_time","_avg_time","_status","_domains")
    fields = readonly_fields

class TrafficDataAdmin(TrafficDataPropertyMixin,admin.DatetimeMixin,djangoadmin.ModelAdmin):
    list_display = ("_start_time","_cluster","_servers","requests","_total_time","_min_time","_max_time","_avg_time","get_remote_sessions","delete_remote_sessions")
    readonly_fields = ("_cluster","_start_time","_end_time","_serverlist","requests","_total_time","_min_time","_max_time","_avg_time","get_remote_sessions","delete_remote_sessions","_status","_domains","_batchid")
    fields = readonly_fields
    ordering = ("-start_time","clusterid")
    list_filter = ['clusterid']
    inlines = [SSOMethodTrafficDataInline]

    def _subreports(self,obj):
        if not obj:
            return ""
        else:
            if obj.cluster is None:
                if obj.clusterid is None:
                    #non cluser env
                    return ""
                else:
                    #overall report
                    return ""
            else:
                #cluster report
                if obj.report_type == models.TrafficReport.DAILY_REPORT:
                    return ""
                else:
                    return ""

              
            return obj.cluster.clusterid if obj.cluster else obj.clusterid
    _subreports.short_description = "Sub Reports"

    def _servers(self,obj):
        if not obj or not obj.servers:
            return ""
        else:
            return len(obj.servers)
    _servers.short_description = "Servers"

    def _serverlist(self,obj):
        if not obj or not obj.servers:
            return ""
        else:
            return mark_safe("<pre>{}\r\n    {}</pre>".format("1 Server" if len(obj.servers) < 2 else "{} Servers".format(len(obj.servers)),"\r\n    ".join(obj.servers)))
    _serverlist.short_description = "Servers"

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

class SSOMethodTrafficReportInline(TrafficDataPropertyMixin,djangoadmin.TabularInline):
    model = models.SSOMethodTrafficReport
    readonly_fields = ("sso_method","requests","_total_time","_min_time","_max_time","_avg_time","_status","_domains")
    fields = readonly_fields

class TrafficReportAdmin(TrafficDataPropertyMixin,admin.DatetimeMixin,djangoadmin.ModelAdmin):
    list_display = ("report_type","_start_time","_cluster","requests","_total_time","_min_time","_max_time","_avg_time","get_remote_sessions","delete_remote_sessions","_subreports")
    readonly_fields = ("_cluster","report_type","_start_time","_end_time","requests","_total_time","_min_time","_max_time","_avg_time","get_remote_sessions","delete_remote_sessions","_status","_domains")
    fields = readonly_fields
    ordering = ("report_type","-start_time",'clusterid')
    list_filter = ['clusterid',"report_type"]
    inlines = [SSOMethodTrafficReportInline]

    traffic_data_list_url_name = 'admin:{}_{}_changelist'.format(models.TrafficData._meta.app_label,models.TrafficData._meta.model_name)
    traffic_report_list_url_name = 'admin:{}_{}_changelist'.format(models.TrafficReport._meta.app_label,models.TrafficReport._meta.model_name)

    def _subreports(self,obj):
        if not obj:
            return ""
        else:
            if obj.cluster is None:
                if obj.clusterid is None:
                    #non cluser env
                    return mark_safe("<A href='{}?clusterid__isnull=Truestart_time__gte={}&end_time__lte={}'>Details</A>".format(reverse(self.traffic_data_list_url_name),self._start_time(obj),self._end_time(obj)))
                else:
                    #overall report
                    if obj.report_type == models.TrafficReport.DAILY_REPORT:
                        return mark_safe("""
                            <A href='{}?report_type={}&cluster__isnull=False&start_time__gte={}&end_time__lte={}'>Cluster Daily Report</A>&nbsp;|&nbsp;
                            <A href='{}?clusterid__isnull=False&start_time__gte={}&end_time__lte={}'>Details</A>""".format(
                            reverse(self.traffic_report_list_url_name),models.TrafficReport.DAILY_REPORT,self._start_time(obj),self._end_time(obj),
                            reverse(self.traffic_data_list_url_name),self._start_time(obj),self._end_time(obj)
                        ))
                    else:
                        return mark_safe("""
                            <A href='{}?report_type={}&clusterid=AUTH2&start_time__gte={}&end_time__lte={}'>Daily Report</A>&nbsp;|&nbsp;
                            <A href='{}?report_type={}&cluster__isnull=False&start_time__gte={}&end_time__lte={}'>Cluster Report</A>""".format(
                            reverse(self.traffic_report_list_url_name),models.TrafficReport.DAILY_REPORT,self._start_time(obj),self._end_time(obj),
                            reverse(self.traffic_report_list_url_name),obj.report_type,self._start_time(obj),self._end_time(obj)
                        ))

            else:
                #cluster report
                if obj.report_type == models.TrafficReport.DAILY_REPORT:
                    return mark_safe("<A href='{}?cluster={}&start_time__gte={}&end_time__lte={}'>Details</A>".format(reverse(self.traffic_data_list_url_name),obj.cluster.id,self._start_time(obj),self._end_time(obj)))
                else:
                    return mark_safe("""
                        <A href='{}?report_type={}&cluster={}&start_time__gte={}&end_time__lte={}'>Daily Report</A>&nbsp;|&nbsp;
                        <A href='{}?cluster={}&start_time__gte={}&end_time__lte={}'>Details</A>""".format(
                        reverse(self.traffic_report_list_url_name),models.TrafficReport.DAILY_REPORT,obj.cluster.id,self._start_time(obj),self._end_time(obj),
                        reverse(self.traffic_data_list_url_name),obj.cluster.id,self._start_time(obj),self._end_time(obj)
                    ))

              
            return obj.cluster.clusterid if obj.cluster else obj.clusterid
    _subreports.short_description = "Sub Reports"

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

