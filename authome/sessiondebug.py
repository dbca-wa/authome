import logging

from django.conf import settings
from django.utils import timezone

import authome.session
logger = logging.getLogger(__name__)

from . import performance

class SessionStore(authome.session.SessionStore):
    """
    Override the cache session store to provide the performance related log
    """
    def load(self):
        try:
            performance.start_processingstep("get_session_from_cache")
            return super().load()
        finally:
            performance.end_processingstep("get_session_from_cache")
            pass
        
