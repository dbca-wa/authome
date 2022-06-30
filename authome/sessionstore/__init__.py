from django.conf import settings

if settings.AUTH2_CLUSTER_ENABLED:
    if settings.DEBUG:
        from .clustersessionstoredebug import SessionStore
    else:
        from .clustersessionstore import SessionStore
else:
    if settings.DEBUG:
        from .sessionstoredebug import SessionStore
    else:
        from .sessionstore import SessionStore
