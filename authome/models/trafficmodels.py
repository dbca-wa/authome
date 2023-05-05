from datetime import timedelta,datetime
import logging

from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField

from .clustermodels import Auth2Cluster
from .. import utils

logger = logging.getLogger(__name__)

class TrafficDataProcessStatus(models.Model):
    cluster = models.ForeignKey(Auth2Cluster, on_delete=models.SET_NULL,null=True,editable=False)
    clusterid = models.CharField(max_length=32,editable=False,null=True,unique=True)
    last_saved_batchid = models.DateTimeField(editable=False,null=True)
    last_processed_batchid = models.DateTimeField(editable=False,null=True)
    disabled = models.BooleanField(default=False)

class TrafficData(models.Model):
    cluster = models.ForeignKey(Auth2Cluster, on_delete=models.SET_NULL,null=True,editable=False)
    clusterid = models.CharField(max_length=32,editable=False,null=True)
    servers = ArrayField(models.CharField(max_length=512,null=False),editable=False,null=True)
    start_time = models.DateTimeField(editable=False,db_index=True)
    end_time = models.DateTimeField(editable=False)
    batchid = models.DateTimeField(editable=False,db_index=True)
    requests = models.PositiveIntegerField(default=0,editable=False)
    total_time = models.FloatField(null=True,editable=False)
    min_time = models.FloatField(null=True,editable=False)
    max_time = models.FloatField(null=True,editable=False)
    avg_time = models.FloatField(null=True,editable=False)
    get_remote_sessions = models.PositiveIntegerField(default=0,editable=False)
    delete_remote_sessions = models.PositiveIntegerField(default=0,editable=False)
    status = models.JSONField(null=True,editable=False)
    domains = models.JSONField(null=True,editable=False)

    class Meta:
        verbose_name_plural = "{}Traffic Data".format(" " * 1)
        unique_together = [["clusterid","start_time","end_time","batchid"]]

class SSOMethodTrafficData(models.Model):
    traffic_data = models.ForeignKey(TrafficData, on_delete=models.CASCADE)
    sso_method = models.CharField(max_length=32,editable=False)
    requests = models.PositiveIntegerField(default=0,editable=False)
    total_time = models.FloatField(null=True,editable=False)
    min_time = models.FloatField(null=True,editable=False)
    max_time = models.FloatField(null=True,editable=False)
    avg_time = models.FloatField(null=True,editable=False)
    status = models.JSONField(null=True,editable=False)
    domains = models.JSONField(null=True,editable=False)

    class Meta:
        verbose_name_plural = "{}auth2 sso method traffic data".format(" " * 0)
        unique_together = [["traffic_data","sso_method"]]

def _start_of_week(dt):
    dt = timezone.localtime(dt)
    today = datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo)
    if settings.START_OF_WEEK_MONDAY:
        if dt.weekday() == 0:
            return today
        else:
            return today - timedelta(days=dt.weekday())
    else:
        if dt.weekday() == 6:
            return today
        else:
            return today - timedelta(days=dt.weekday() + 1)

def _end_of_week(dt):
    return _start_of_week(dt) + timedelta(days=7)

def _start_of_day(dt):
    dt = timezone.localtime(dt)
    return datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo)

def _end_of_day(dt):
    dt = timezone.localtime(dt)
    return datetime(dt.year,dt.month,dt.day,tzinfo=dt.tzinfo) + timedelta(days=1)

def _start_of_month(dt):
    dt = timezone.localtime(dt)
    return datetime(dt.year,dt.month,1,tzinfo=dt.tzinfo)

def _end_of_month(dt):
    dt = timezone.localtime(dt)
    return datetime(dt.year,dt.month + 1,1,tzinfo=dt.tzinfo) if dt.month < 12 else datetime(dt.year + 1,1,1,tzinfo=dt.tzinfo)



class TrafficReport(models.Model):
    DAILY_REPORT = 1
    WEEKLY_REPORT = 2
    MONTHLY_REPORT = 3
    REPORT_TYPES = [
      (DAILY_REPORT,"Daily Report"),
      (WEEKLY_REPORT,"Weekly Report"),
      (MONTHLY_REPORT,"Monthly Report")
    ]
    REPORTS = [
        (DAILY_REPORT,'Daily Report',_start_of_day,_end_of_day),
        (WEEKLY_REPORT,'Weekly Report',_start_of_week,_end_of_week),
        (MONTHLY_REPORT,'Monthly Report',_start_of_month,_end_of_month)
    ]
    REPORT_NAMES = dict(REPORT_TYPES)

    cluster = models.ForeignKey(Auth2Cluster, on_delete=models.SET_NULL,null=True,editable=False)
    clusterid = models.CharField(max_length=32,editable=False,null=True)
    report_type = models.PositiveSmallIntegerField(choices=REPORT_TYPES)
    start_time = models.DateTimeField(editable=False,db_index=True)
    end_time = models.DateTimeField(editable=False)
    requests = models.PositiveIntegerField(default=0,editable=False)
    total_time = models.FloatField(null=True,editable=False)
    min_time = models.FloatField(null=True,editable=False)
    max_time = models.FloatField(null=True,editable=False)
    avg_time = models.FloatField(null=True,editable=False)
    status = models.JSONField(null=True,editable=False)
    get_remote_sessions = models.PositiveIntegerField(default=0,editable=False)
    delete_remote_sessions = models.PositiveIntegerField(default=0,editable=False)
    domains = models.JSONField(null=True,editable=False)

    class Meta:
        verbose_name_plural = "{}Traffic Report".format(" " * 1)
        unique_together = [["clusterid","report_type","start_time"]]

    @classmethod
    def get_reportname(cls,report_type):
        return cls.REPORT_NAMES.get(report_type,str(report_type))
        

class SSOMethodTrafficReport(models.Model):
    report = models.ForeignKey(TrafficReport, on_delete=models.CASCADE)
    sso_method = models.CharField(max_length=32,editable=False)
    requests = models.PositiveIntegerField(default=0,editable=False)
    total_time = models.FloatField(null=True,editable=False)
    min_time = models.FloatField(null=True,editable=False)
    max_time = models.FloatField(null=True,editable=False)
    avg_time = models.FloatField(null=True,editable=False)
    status = models.JSONField(null=True,editable=False)
    domains = models.JSONField(null=True,editable=False)

    class Meta:
        verbose_name_plural = "{}auth2 sso method traffic report".format(" " * 0)
        unique_together = [["report","sso_method"]]

