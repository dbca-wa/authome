import traceback
import logging

from django.conf import settings

from .models import *
from .tcontrolmodels import *
from .clustermodels import *
from .trafficmodels import *
from .debugmodels import *

logger = logging.getLogger(__name__)

def initialize():
    if settings.AUTH2_CLUSTER_ENABLED:
        logger.debug("Register auth2 cluster server '{}'".format(settings.AUTH2_CLUSTERID))
        #load cache
        try:
            Auth2Cluster.register()
            cache.refresh_auth2_clusters(True)
        except:
            if not settings.IGNORE_LOADING_ERROR:
                raise Exception("Failed to load Auth2Cluster cache during server starting.{}".format(traceback.format_exc()))    
        
    
    logger.debug("Begin to load authorization cache")
    try:
        cache.refresh_authorization_cache(True)
    except:
        if not settings.IGNORE_LOADING_ERROR:
            raise Exception("Failed to load UserGroup and UserGroupAuthorization cache during server starting.{}".format(traceback.format_exc()))
    
    if settings.TRAFFICCONTROL_ENABLED:
        logger.debug("Begin to load TrafficControl cache")
        try:
            cache.refresh_tcontrol_cache(True)
        except:
            if not settings.IGNORE_LOADING_ERROR:
                raise Exception("Failed to load TrafficControl cache during server starting.{}".format(traceback.format_exc()))
        
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
    
