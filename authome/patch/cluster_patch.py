from django.conf import settings

#django.contrib.sessions.middleware is hard coded in the django code, dynamically override the middleware with the customzied cluster supported session middleware
if settings.AUTH2_CLUSTER_ENABLED:
    from django.contrib.sessions import middleware
    from ..middleware  import ClusterSessionMiddleware
    middleware.SessionMiddleware = ClusterSessionMiddleware
else:
    from django.contrib.sessions import middleware
    from ..middleware  import SessionMiddleware
    middleware.SessionMiddleware = SessionMiddleware

