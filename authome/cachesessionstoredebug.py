import logging

from django.conf import settings
from django.utils import timezone

import authome.cachesessionstore
logger = logging.getLogger(__name__)

from . import performance

class SessionStore(authome.cachesessionstore.SessionStore):
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

    def create(self):
        try:
            performance.start_processingstep("create_session")
            return super().create()
        finally:
            performance.end_processingstep("create_session")
            pass

        
    def save(self, must_create=False):
        try:
            performance.start_processingstep("save_session_in_cache")
            return super().save(must_create=must_create)
        finally:
            performance.end_processingstep("save_session_in_cache")
            pass


    def delete(self, session_key=None):
        try:
            performance.start_processingstep("delete_session_from_cache")
            return super().delete(session_key=session_key)
        finally:
            performance.end_processingstep("delete_session_from_cache")
            pass

    def exists(self, session_key):
        try:
            performance.start_processingstep("check_exists_in_cache")
            return super().exists(session_key)
        finally:
            performance.end_processingstep("check_exists_in_cache")
            pass
