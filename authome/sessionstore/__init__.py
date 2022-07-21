from django.conf import settings

if settings.AUTH2_CLUSTER_ENABLED:
    from .clustersessionstore import SessionStore,StandaloneSessionStore
else:
    from .sessionstore import SessionStore
