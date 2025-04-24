from datetime import timedelta,datetime
import logging

from django.db import models as django_models
from django.conf import settings
from django.utils import timezone
from django.contrib.postgres.fields import ArrayField

from .clustermodels import Auth2Cluster
from .. import utils

logger = logging.getLogger(__name__)

class TrafficDataProcessStatus(django_models.Model):
    cluster = django_models.ForeignKey(Auth2Cluster, on_delete=django_models.SET_NULL,null=True,editable=False)
    clusterid = django_models.CharField(max_length=32,editable=False,null=True,unique=True)
    last_saved_batchid = django_models.DateTimeField(editable=False,null=True)
    last_processed_batchid = django_models.DateTimeField(editable=False,null=True)
    disabled = django_models.BooleanField(default=False)

class TrafficData(django_models.Model):
    cluster = django_models.ForeignKey(Auth2Cluster, on_delete=django_models.SET_NULL,null=True,editable=False)
    clusterid = django_models.CharField(max_length=32,editable=False,null=True)
    servers = ArrayField(django_models.CharField(max_length=512,null=False),editable=False,null=True)
    start_time = django_models.DateTimeField(editable=False,db_index=True)
    end_time = django_models.DateTimeField(editable=False)
    batchid = django_models.DateTimeField(editable=False,db_index=True)
    requests = django_models.PositiveIntegerField(default=0,editable=False)
    total_time = django_models.FloatField(null=True,editable=False)
    min_time = django_models.FloatField(null=True,editable=False)
    max_time = django_models.FloatField(null=True,editable=False)
    avg_time = django_models.FloatField(null=True,editable=False)
    redis_requests = django_models.PositiveIntegerField(default=0,editable=False)
    redis_avg_time = django_models.FloatField(null=True,editable=False)
    db_requests = django_models.PositiveIntegerField(default=0,editable=False)
    db_avg_time = django_models.FloatField(null=True,editable=False)
    get_remote_sessions = django_models.PositiveIntegerField(default=0,editable=False)
    delete_remote_sessions = django_models.PositiveIntegerField(default=0,editable=False)
    status = django_models.JSONField(null=True,editable=False)
    domains = django_models.JSONField(null=True,editable=False)

    class Meta:
        verbose_name_plural = "{}Traffic Data".format(" " * 5)
        unique_together = [["clusterid","start_time","end_time","batchid"]]

class SSOMethodTrafficData(django_models.Model):
    traffic_data = django_models.ForeignKey(TrafficData, on_delete=django_models.CASCADE)
    sso_method = django_models.CharField(max_length=32,editable=False)
    requests = django_models.PositiveIntegerField(default=0,editable=False)
    total_time = django_models.FloatField(null=True,editable=False)
    min_time = django_models.FloatField(null=True,editable=False)
    max_time = django_models.FloatField(null=True,editable=False)
    avg_time = django_models.FloatField(null=True,editable=False)
    status = django_models.JSONField(null=True,editable=False)
    domains = django_models.JSONField(null=True,editable=False)

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



class TrafficReport(django_models.Model):
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

    cluster = django_models.ForeignKey(Auth2Cluster, on_delete=django_models.SET_NULL,null=True,editable=False)
    clusterid = django_models.CharField(max_length=32,editable=False,null=True)
    report_type = django_models.PositiveSmallIntegerField(choices=REPORT_TYPES)
    start_time = django_models.DateTimeField(editable=False,db_index=True)
    end_time = django_models.DateTimeField(editable=False)
    requests = django_models.PositiveIntegerField(default=0,editable=False)
    total_time = django_models.FloatField(null=True,editable=False)
    min_time = django_models.FloatField(null=True,editable=False)
    max_time = django_models.FloatField(null=True,editable=False)
    avg_time = django_models.FloatField(null=True,editable=False)
    status = django_models.JSONField(null=True,editable=False)
    redis_requests = django_models.PositiveIntegerField(default=0,editable=False)
    redis_avg_time = django_models.FloatField(null=True,editable=False)
    db_requests = django_models.PositiveIntegerField(default=0,editable=False)
    db_avg_time = django_models.FloatField(null=True,editable=False)
    get_remote_sessions = django_models.PositiveIntegerField(default=0,editable=False)
    delete_remote_sessions = django_models.PositiveIntegerField(default=0,editable=False)
    domains = django_models.JSONField(null=True,editable=False)

    class Meta:
        verbose_name_plural = "{}Traffic Report".format(" " * 4)
        unique_together = [["clusterid","report_type","start_time"]]

    @classmethod
    def get_reportname(cls,report_type):
        return cls.REPORT_NAMES.get(report_type,str(report_type))
        

class SSOMethodTrafficReport(django_models.Model):
    report = django_models.ForeignKey(TrafficReport, on_delete=django_models.CASCADE)
    sso_method = django_models.CharField(max_length=32,editable=False)
    requests = django_models.PositiveIntegerField(default=0,editable=False)
    total_time = django_models.FloatField(null=True,editable=False)
    min_time = django_models.FloatField(null=True,editable=False)
    max_time = django_models.FloatField(null=True,editable=False)
    avg_time = django_models.FloatField(null=True,editable=False)
    status = django_models.JSONField(null=True,editable=False)
    domains = django_models.JSONField(null=True,editable=False)

    class Meta:
        verbose_name_plural = "{}auth2 sso method traffic report".format(" " * 0)
        unique_together = [["report","sso_method"]]

