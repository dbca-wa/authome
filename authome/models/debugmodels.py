from django.db import models
import logging
from django.conf  import settings
from django.utils import timezone

from ..cache import cache
from .. import utils

logger = logging.getLogger(__name__)

class DebugLog(models.Model):
    INFO = 0,
    CREATE_COOKIE = 10
    UPDATE_COOKIE = 11
    DELETE_COOKIE = 12

    UPGRADE_SESSION = 20
    UPGRADE_UPGRADED_SESSION = 21
    UPGRADE_NONEXIST_SESSION = 22

    MIGRATE_SESSION = 30
    MIGRATE_MIGRATED_SESSION = 31
    MIGRATE_NONEXIST_SESSION = 32

    MOVE_PREVIOUS_SESSION = 40
    MOVE_MOVED_PREVIOUS_SESSION = 41
    MOVE_NONEXIST_PREVIOUS_SESSION = 42

    AUTH2_CLUSTER_NOTAVAILABLE = 50
    
    WARNING = 100
    UPGRADE_NONEXIST_UPGRADED_SESSION = 123
    MIGRATE_NONEXIST_MIGRATED_SESSION = 133
    MOVE_NONEXIST_MOVED_PREVIOUS_SESSION = 143

    ERROR = 200
    LB_HASH_KEY_NOT_MATCH = 201
    DOMAIN_NOT_MATCH = 202
    SESSION_COOKIE_HACKED = 210

    CATEGORIES = [
        (CREATE_COOKIE , "Create cookie"),
        (UPDATE_COOKIE , "Update cookie"),
        (DELETE_COOKIE , "Delete cookie"),

        (UPGRADE_SESSION , "Upgrade session"),
        (UPGRADE_UPGRADED_SESSION , "Upgrade upgraded session"),
        (UPGRADE_NONEXIST_SESSION , "Upgrade non-exist session"),

        (MIGRATE_SESSION , "Migrate session"),
        (MIGRATE_MIGRATED_SESSION , "Migrate migrated session"),
        (MIGRATE_NONEXIST_SESSION , "Migrate non-exist session"),
    
        (MOVE_PREVIOUS_SESSION , "Move previous session"),
        (MOVE_MOVED_PREVIOUS_SESSION , "Move moved previous session"),
        (MOVE_NONEXIST_PREVIOUS_SESSION , "Move non-exist previous session"),

        (AUTH2_CLUSTER_NOTAVAILABLE , "Auth2 Cluster Not Available"),

        (UPGRADE_NONEXIST_UPGRADED_SESSION , "Upgrade non-exist upgraded session"),
        (MIGRATE_NONEXIST_MIGRATED_SESSION , "Migrate non-exist migrated session"),
        (MOVE_NONEXIST_MOVED_PREVIOUS_SESSION , "Move non-exist moved previous session"),

        (LB_HASH_KEY_NOT_MATCH , "LB key not match"),
        (DOMAIN_NOT_MATCH, "Domain not match"),
        (SESSION_COOKIE_HACKED,"Session cookie hacked"),

        (ERROR,"Error")

    ]
    logtime = models.DateTimeField(auto_now_add=timezone.now,db_index=True)
    lb_hash_key = models.CharField(max_length=128,editable=False,null=True,db_index=True)
    clusterid = models.CharField(max_length=32,editable=False,null=True,db_index=True)
    session_clusterid = models.CharField(max_length=32,editable=False,null=True,db_index=True)
    session_key = models.CharField(max_length=128,editable=False,null=True,db_index=True)
    source_session_cookie = models.CharField(max_length=128,editable=False,null=True)
    target_session_cookie = models.CharField(max_length=128,editable=False,null=True)
    email = models.CharField(max_length=128,editable=False,null=True,db_index=True)
    request = models.CharField(max_length=256,editable=False,null=True,db_index=True)
    category = models.PositiveSmallIntegerField(choices=CATEGORIES,default=CREATE_COOKIE)
    useragent = models.CharField(max_length=512,editable=False,null=True)
    message = models.TextField(editable=False,null=True)

    class Meta:
        verbose_name_plural = "{}Auth2 Logs".format(" " * 0)

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
    def log(cls,category,lb_hash_key,session_clusterid,session_key,source_session_cookie,message,target_session_cookie=None,userid=None):
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
            request=utils.get_request_path()[:255],
            useragent=utils.get_useragent()
        )
        log.save()
        cls.print(log)

    @classmethod
    def log_if_true(cls,condition,category,lb_hash_key,session_clusterid,session_key,source_session_cookie,message,target_session_cookie=None,userid=None):
        if not condition:
            return
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
            request=utils.get_request_path()[:255],
            useragent=utils.get_useragent()
        )
        log.save()
        cls.print(log)



