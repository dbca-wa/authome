import logging

import  django.contrib.sessions.backends.cache
from django.conf import settings

logger = logging.getLogger(__name__)

class SessionStore(django.contrib.sessions.backends.cache.SessionStore):
    cache_key_prefix = "{}_session".format(settings.CACHE_KEY_PREFIX) if settings.CACHE_KEY_PREFIX else "session"

