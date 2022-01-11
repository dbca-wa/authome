import logging

from django.conf import settings
from django.utils import timezone

import authome.session
logger = logging.getLogger(__name__)

class SessionStore(authome.session.SessionStore):
    """
    Override the cache session store to provide the performance related log
    """
    def load(self):
        logger.debug("Start to load session from cache")
        now = timezone.now()
        try:
            return super().load()
        finally:
            diff = timezone.now() - now
            logger.debug("Spend {} milliseconds to load session data from cache".format(round((diff.seconds * 1000 + diff.microseconds)/1000)))
        
