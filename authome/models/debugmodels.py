from django.db import models as django_models
import traceback
import logging
from django.conf  import settings
from django.utils import timezone

from ..cache import cache
from .. import utils

logger = logging.getLogger(__name__)

class DebugLog(django_models.Model):
    INFO = 0,
    CREATE_COOKIE = 10
    UPDATE_COOKIE = 11
    DELETE_COOKIE = 12

    UPGRADE_SESSION = 20
    SESSION_ALREADY_UPGRADED = 21
    UPGRADE_NONEXIST_SESSION = 22

    MIGRATE_SESSION = 30
    SESSION_ALREADY_MIGRATED = 31
    MIGRATE_NONEXIST_SESSION = 32

    MOVE_SESSION = 40
    SESSION_ALREADY_MOVED = 41
    MOVE_NONEXIST_SESSION = 42

    AUTH2_CLUSTER_NOTAVAILABLE = 50

    WARNING = 100
    INTERCONNECTION_TIMEOUT = 101
    AUTH_TOO_SLOW = 102

    ERROR = 200
    LB_HASH_KEY_NOT_MATCH = 201
    DOMAIN_NOT_MATCH = 202
    SESSION_COOKIE_HACKED = 210

    USER_TRAFFIC_CONTROL = 300
    IP_TRAFFIC_CONTROL = 301
    CONCURRENCY_TRAFFIC_CONTROL = 302
    TRAFFIC_CONTROL_ERROR = 399

    CATEGORIES = [
        (CREATE_COOKIE , "Create cookie"),
        (UPDATE_COOKIE , "Update cookie"),
        (DELETE_COOKIE , "Delete cookie"),

        (UPGRADE_SESSION , "Upgrade session"),
        (SESSION_ALREADY_UPGRADED , "Session already upgraded"),
        (UPGRADE_NONEXIST_SESSION , "Upgrade non-exist session"),

        (MIGRATE_SESSION , "Migrate session"),
        (SESSION_ALREADY_MIGRATED , "Session already migrated"),
        (MIGRATE_NONEXIST_SESSION , "Migrate non-exist session"),
    
        (MOVE_SESSION , "Move session"),
        (SESSION_ALREADY_MOVED , "Session already moved"),
        (MOVE_NONEXIST_SESSION , "Move non-exist session"),

        (AUTH2_CLUSTER_NOTAVAILABLE , "Auth2 Cluster Not Available"),
        (INTERCONNECTION_TIMEOUT, "Auth2 Interconnection Timeout"),
        (AUTH_TOO_SLOW, "Authentication Too Slow"),

        (LB_HASH_KEY_NOT_MATCH , "LB key not match"),
        (DOMAIN_NOT_MATCH, "Domain not match"),
        (SESSION_COOKIE_HACKED,"Session cookie hacked"),

        (USER_TRAFFIC_CONTROL,"User Traffic Control"),
        (IP_TRAFFIC_CONTROL,"IP Traffic Control"),
        (CONCURRENCY_TRAFFIC_CONTROL,"Concurrency Traffic Control"),
        (TRAFFIC_CONTROL_ERROR,"Traffic Control Error"),

        (ERROR,"Error")

    ]
    logtime = django_models.DateTimeField(auto_now_add=timezone.now,db_index=True)
    lb_hash_key = django_models.CharField(max_length=128,editable=False,null=True,db_index=True)
    clusterid = django_models.CharField(max_length=32,editable=False,null=True,db_index=True)
    session_clusterid = django_models.CharField(max_length=32,editable=False,null=True,db_index=True)
    session_key = django_models.CharField(max_length=128,editable=False,null=True,db_index=True)
    source_session_cookie = django_models.CharField(max_length=128,editable=False,null=True)
    target_session_cookie = django_models.CharField(max_length=128,editable=False,null=True)
    email = django_models.CharField(max_length=128,editable=False,null=True,db_index=True)
    request = django_models.CharField(max_length=256,editable=False,null=True,db_index=True)
    category = django_models.PositiveSmallIntegerField(choices=CATEGORIES,default=CREATE_COOKIE)
    useragent = django_models.CharField(max_length=512,editable=False,null=True)
    message = django_models.TextField(editable=False,null=True)

    class Meta:
        verbose_name_plural = "{}Auth2 Logs".format(" " * 3)

    @classmethod
    def attach_request(cls,request):
        utils.attach_request(request)

    @classmethod
    def get_email(cls,userid):
        from ..patch import load_user
        if userid:
            try:
                return load_user(userid).email
            except:
                return None
        else:
            return None

    @classmethod
    def get_lb_hash_key(cls,session=None,session_key=None):
        import authome.sessionstore.clustersessionstore
        if session_key:
            get_source_session_key
        elif isinstance(session,authome.sessionstore.clustersessionstore.SessionStore):
            return session._lb_hash_key
        else:
            return None

    @classmethod
    def get_clusterid(cls,session):
        import authome.sessionstore.clustersessionstore
        if isinstance(session,authome.sessionstore.clustersessionstore.SessionStore):
            return session._auth2_clusterid
        else:
            return None

    @classmethod
    def print(cls,log):
        if log.category >= cls.WARNING:
            return

        logger.debug("{}, lb_hash_key={}, clusterid={}, session_clusterid={}, session_key={}, source_session_cookie={}, target_session_cookie={}, email={}, request={}".format(log.message,log.lb_hash_key,log.clusterid,log.session_clusterid,log.session_key,log.source_session_cookie,log.target_session_cookie,log.email,log.request))


    @classmethod
    def log(cls,category,lb_hash_key,session_clusterid,session_key,source_session_cookie,message,target_session_cookie=None,userid=None,request=None):
        if settings.DEBUG:
            cls.warning(category,lb_hash_key,session_clusterid,session_key,source_session_cookie,message,target_session_cookie=target_session_cookie,userid=userid,request=request)

    @classmethod
    def log_if_true(cls,condition,category,lb_hash_key,session_clusterid,session_key,source_session_cookie,message,target_session_cookie=None,userid=None,request=None):
        if settings.DEBUG:
            cls.warning_if_true(condition,category,lb_hash_key,session_clusterid,session_key,source_session_cookie,message,target_session_cookie=target_session_cookie,userid=userid,request=request)

    @classmethod
    def warning(cls,category,lb_hash_key,session_clusterid,session_key,source_session_cookie,message,target_session_cookie=None,userid=None,request=None,useremail=None):
        try:
            path = utils.get_request_path(request)
            path = path[:255] if path else path
            log = DebugLog(
                lb_hash_key = lb_hash_key,
                clusterid = settings.AUTH2_CLUSTERID if settings.AUTH2_CLUSTER_ENABLED else None,
                session_clusterid = (session_clusterid if session_clusterid else (cache.default_auth2_cluster.clusterid if cache.default_auth2_cluster else "N/A")) if settings.AUTH2_CLUSTER_ENABLED else None,
                session_key = session_key,
                source_session_cookie = source_session_cookie,
                target_session_cookie = target_session_cookie,
                message = message,
                category=category,
                email = useremail if useremail else cls.get_email(userid),
                request=path,
                useragent=utils.get_useragent(request)
            )
            log.save()
        except:
            logger.error("Failed to log the message '{}' to DebugLog.{}".format(message,traceback.format_exc()))

    @classmethod
    def warning_if_true(cls,condition,category,lb_hash_key,session_clusterid,session_key,source_session_cookie,message,target_session_cookie=None,userid=None,request=None):
        try:
            if not condition:
                return
            path = utils.get_request_path(request)
            path = path[:255] if path else path
            log = DebugLog(
                lb_hash_key = lb_hash_key,
                clusterid = settings.AUTH2_CLUSTERID if settings.AUTH2_CLUSTER_ENABLED else None,
                session_clusterid = (session_clusterid if session_clusterid else (cache.default_auth2_cluster.clusterid if cache.default_auth2_cluster else "N/A")) if settings.AUTH2_CLUSTER_ENABLED else None,
                session_key = session_key,
                source_session_cookie = source_session_cookie,
                target_session_cookie = target_session_cookie,
                message = message,
                category=category,
                email = cls.get_email(userid),
                request=path,
                useragent=utils.get_useragent(request)
            )
            log.save()
        except:
            logger.error("Failed to log the message '{}' to DebugLog.{}".format(message,traceback.format_exc()))

    @classmethod
    def tcontrol(cls,category,tcontrol_name,ip,email,message):
        try:
            log = DebugLog(
                clusterid = settings.AUTH2_CLUSTERID if settings.AUTH2_CLUSTER_ENABLED else None,
                lb_hash_key = ip,
                message = message,
                category=category,
                email = email,
                request=tcontrol_name
            )
            log.save()
        except:
            logger.error("Failed to log the message '{}' to DebugLog.{}".format(message,traceback.format_exc()))

