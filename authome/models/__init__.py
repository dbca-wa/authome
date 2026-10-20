import traceback
import logging

from django.conf import settings

from .models import *
from .clustermodels import *
from .trafficmodels import *
from .debugmodels import *

logger = logging.getLogger(__name__)

def initialize():
    """
    Can't call it simply during application initialization because of following reason
    In gunicorn environment, gunicorn will folk the master process to create the worker process, if calling this method during master process intialization, master process will create the database connection, and during folking process, the database connection will be cloned to worker process, that will cause error "SSL error: decryption failed or bad record mac".
    The solution is calling it in event hook 'post_folk' of gunicorn.
    """
    if settings.AUTH2_CLUSTER_ENABLED:
        logger.debug("Register auth2 cluster server '{}'".format(settings.AUTH2_CLUSTERID))
        #load cache
        try:
            Auth2Cluster.register()
            cache.refresh_auth2_clusters(True)
        except:
            if not settings.IGNORE_LOADING_ERROR:
                raise Exception("Failed to load Auth2Cluster cache during server starting.{}".format(traceback.format_exc()))    
        finally:
            logger.debug("Succeed to register auth2 cluster server '{}'".format(settings.AUTH2_CLUSTERID))
            pass

        
    
    logger.debug("Begin to load authorization cache")
    try:
        cache.refresh_authorization_cache(True)
    except:
        if not settings.IGNORE_LOADING_ERROR:
            raise Exception("Failed to load UserGroup and UserGroupAuthorization cache during server starting.{}".format(traceback.format_exc()))
    
    logger.debug("Begin to load IDP cache")
    try:
        cache.refresh_idp_cache(True)
    except:
        if not settings.IGNORE_LOADING_ERROR:
            raise Exception("Failed to load IdentityProvider cache during server starting.{}".format(traceback.format_exc()))
        
    logger.debug("Begin to load user flow cache")
    try:
        cache.refresh_userflow_cache(True)
    except:
        if not settings.IGNORE_LOADING_ERROR:
            raise Exception("Failed to load CustomizableUserflow cache during server starting.{}".format(traceback.format_exc()))
