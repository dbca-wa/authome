from django.conf import settings
from django.urls import include, path

import authome.patch
from .. import models
from .urls import urlpatterns,logger
from .. import views
from .  import selfserviceurls

handler400 = views.handler400

if settings.AUTH2_CLUSTER_ENABLED :
    from . import clusterurls
    urlpatterns.append(path('cluster/',include((clusterurls.urlpatterns,'cluster'),namespace="cluster")))
    
urlpatterns.append(path('sso/selfservice/',include((selfserviceurls.urlpatterns,'selfservice'),namespace="selfservice")))

if settings.TESTMODE:
    from . import testurls
    urlpatterns.append(path('test/',include((testurls.urlpatterns,'test'),namespace="test")))
    logger.info("Start auth2 in testing mode")

models.initialize()
