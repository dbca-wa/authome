import traceback

from django.conf import settings

from .models import *
from .clustermodels import *
from .models import _ArrayField


def initialize():
    if settings.AUTH2_CLUSTER_ENABLED :
        #load cache
        try:
            Auth2Cluster.register()
            cache.refresh_auth2_clusters(True)
        except:
            if not settings.IGNORE_LOADING_ERROR:
                raise Exception("Failed to load Auth2Cluster cache during server starting.{}".format(traceback.format_exc()))    
        
    
    try:
        cache.refresh_authorization_cache(True)
    except:
        if not settings.IGNORE_LOADING_ERROR:
            raise Exception("Failed to load UserGroup and UserGroupAuthorization cache during server starting.{}".format(traceback.format_exc()))
        
    try:
        cache.refresh_idp_cache(True)
    except:
        if not settings.IGNORE_LOADING_ERROR:
            raise Exception("Failed to load IdentityProvider cache during server starting.{}".format(traceback.format_exc()))
        
    try:
        cache.refresh_userflow_cache(True)
    except:
        if not settings.IGNORE_LOADING_ERROR:
            raise Exception("Failed to load CustomizableUserflow cache during server starting.{}".format(traceback.format_exc()))
    
