import logging

import  django.contrib.sessions.backends.cache
from django.utils import timezone

logger = logging.getLogger(__name__)

KEY_PREFIX = "django.contrib.sessions.cache"
class SessionStore(django.contrib.sessions.backends.cache.SessionStore):
    def load(self):
        logger.debug("Start to load session from cache")
        now = timezone.now()
        try:
            return super().load()
        finally:
            diff = timezone.now() - now
            logger.debug("Spend {} milliseconds to load session data from cache".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
        
