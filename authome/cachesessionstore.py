import logging
import string

from django.conf import settings
from django.utils import timezone
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY

from django.contrib.sessions.backends.base import (
    CreateError, SessionBase, UpdateError,VALID_KEY_CHARS
)
from django.core.cache import caches
from django.utils.crypto import  get_random_string

logger = logging.getLogger(__name__)

if settings.SESSION_CACHES == 0:
    get_firstsessioncache = lambda :None
elif settings.SESSION_CACHES == 1:
    get_firstsessioncache = lambda :caches[settings.SESSION_CACHE_ALIAS]
else:
    get_firstsessioncache = lambda :caches["session0"]

firstsessioncache = get_firstsessioncache()

process_seq_key = "{}:{}".format(settings.CACHE_KEY_PREFIX,settings.SESSION_COOKIE_NAME) if settings.CACHE_KEY_PREFIX else settings.SESSION_COOKIE_NAME

VALID_DIGITIAL_CHARS = string.digits + string.ascii_uppercase
def convert_decimal(number,decimal):
    remain_number = number
    converted_number = None
    while remain_number is not None:
        if remain_number < decimal:
            c = VALID_DIGITIAL_CHARS[remain_number]
            remain_number = None
        else:
            c =  VALID_DIGITIAL_CHARS[remain_number % decimal]
            remain_number = int(remain_number / decimal)

        if converted_number:
            converted_number =  c + converted_number
        else:
            converted_number =  c


    return converted_number
        
class _AbstractSessionStore(SessionBase):
    cache_key_prefix = "{}-session:".format(settings.CACHE_KEY_PREFIX) if settings.CACHE_KEY_PREFIX else "session:"

    def _get_cache(self,session_key=None):
        return None

    @property
    def cache_key(self):
        return self.cache_key_prefix + self._get_or_create_session_key()


    def get_session_cookie_age(self):
        if self.get(USER_SESSION_KEY):
            return settings.SESSION_COOKIE_AGE
        else:
            return settings.GUEST_SESSION_AGE

    def get_cache_key(self,session_key=None):
        if not session_key:
            session_key = self.session_key
        return self.cache_key_prefix + session_key


    def load(self):
        try:
            session_data = self._get_cache().get(self.cache_key)
        except Exception:
            # Some backends (e.g. memcache) raise an exception on invalid
            # cache keys. If this happens, reset the session. See #17810.
            session_data = None
        if session_data is not None:
            return session_data
        self._session_key = None
        return {}

    def create(self):
        # Because a cache can fail silently (e.g. memcache), we don't know if
        # we are failing to create a new session because of a key collision or
        # because the cache is missing. So we try for a (large) number of times
        # and then raise an exception. That's the risk you shoulder if using
        # cache backing.
        for i in range(10000):
            self._session_key = self._get_new_session_key()
            try:
                self.save(must_create=True)
            except CreateError:
                continue
            self.modified = True
            return
        raise RuntimeError(
            "Unable to create a new session key. "
            "It is likely that the cache is unavailable.")

    def save(self, must_create=False):
        if self.session_key is None:
            return self.create()
        if must_create:
            func = self._get_cache().add
        else:
            func = self._get_cache().set
        result = func(self.cache_key,
                      self._get_session(no_load=must_create),
                      self.get_expiry_age())
        if must_create and not result:
            raise CreateError

    def exists(self, session_key):
        return bool(session_key) and (self.cache_key_prefix + session_key) in self._get_cache(session_key)

    def delete(self, session_key=None):
        if session_key is None:
            if self.session_key is None:
                return
            session_key = self.session_key
        self._get_cache(session_key).delete(self.cache_key_prefix + session_key)

    @classmethod
    def clear_expired(cls):
        pass

if settings.SYNC_MODE:
    class _BaseSessionStore(_AbstractSessionStore):
        _process_prefix = None

        @classmethod
        def _init_process_prefix(cls):
            if not cls._process_prefix:
                firstsessioncache.get_or_set(process_seq_key,0,timeout=None)
                cls._process_prefix = convert_decimal(firstsessioncache.incr(process_seq_key),36)
                logger.info("Got process prefix({}) for session key.".format(cls._process_prefix))


        @classmethod
        def _get_process_prefix(cls):
            if not cls._process_prefix:
                cls._init_process_prefix()

            return cls._process_prefix

        def _get_new_session_key(self):
            "Return session key that isn't being used."
            cls = self.__class__
            while True:
                session_key = "{}-{}".format(cls._get_process_prefix(),get_random_string(32, VALID_KEY_CHARS))
                if not self.exists(session_key):
                    return session_key

else:
    import queue
    class _BaseSessionStore(_AbstractSessionStore):
        _process_prefix = None

        @classmethod
        def _init_process_prefix(cls):
            cls._process_prefix = queue.Queue(maxsize=10)
            firstsessioncache.get_or_set(process_seq_key,0,timeout=None)
            n = firstsessioncache.incr(process_seq_key,10) - 9
            for i in range(n,n + 10):
                cls._process_prefix.put(convert_decimal(i,36))


        @classmethod
        def _get_process_prefix(cls):
            if not cls._process_prefix:
                cls._init_process_prefix()

            return cls._process_prefix.get()

        def _get_new_session_key(self):
            "Return session key that isn't being used."
            cls = self.__class__
            prefix = cls._get_process_prefix()
            try:
                while True:
                    session_key = "{}-{}".format(prefix,get_random_string(32, VALID_KEY_CHARS))
                    if not self.exists(session_key):
                        return session_key
            finally:
                cls._process_prefix.put(prefix)


if settings.SESSION_CACHES == 1:
    class SessionStore(_BaseSessionStore):
        def __init__(self, session_key=None):
            self._cache = caches[settings.SESSION_CACHE_ALIAS]
            super().__init__(session_key)

        def _get_cache(self,session_key=None):
            return self._cache
else:
    class SessionStore(_BaseSessionStore):
        def _get_cache(self,session_key=None):
            if not session_key:
                session_key = self.cache_key
            return caches[settings.SESSION_CACHE_ALIAS(session_key)]


