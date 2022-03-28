import logging
from datetime import timedelta
import string

from django.conf import settings
from django.utils import timezone
from django.contrib.auth import SESSION_KEY as USER_SESSION_KEY

from django.contrib.sessions.backends.base import (
    CreateError, SessionBase, UpdateError
)
from django.core.cache import caches
from django.utils.crypto import  get_random_string

from . import models

logger = logging.getLogger(__name__)

if settings.SESSION_CACHES == 0:
    get_firstsessioncache = lambda :None
elif settings.SESSION_CACHES == 1:
    get_firstsessioncache = lambda :caches[settings.SESSION_CACHE_ALIAS]
else:
    get_firstsessioncache = lambda :caches["session0"]

firstsessioncache = get_firstsessioncache()

process_seq_key = "{}:{}".format(settings.CACHE_KEY_PREFIX,settings.SESSION_COOKIE_NAME) if settings.CACHE_KEY_PREFIX else settings.SESSION_COOKIE_NAME

VALID_DIGITIAL_CHARS = string.digits + string.ascii_lowercase
VALID_KEY_CHARS = VALID_DIGITIAL_CHARS

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

def to_decimal(s,decimal):
    number = 0
    s = s.lower()
    l = len(s)
    for i in range(l):
        c = s[i]
        p = l - 1 - i
        if p == 0:
            number += VALID_DIGITIAL_CHARS.index(c)
        else:
            number += VALID_DIGITIAL_CHARS.index(c) * pow(decimal,p)

    return number

    

        
class _AbstractSessionStore(SessionBase):
    cache_key_prefix = "{}-session:".format(settings.CACHE_KEY_PREFIX) if settings.CACHE_KEY_PREFIX else "session:"
    _idppk = None
    expired_session_key = None

    def __init__(self, session_key=None):
        super().__init__(session_key)
        if session_key and "-" in session_key:
            self._idppk = to_decimal(session_key[0:session_key.index("-")],36)


    @property
    def expireat(self):
        try:
            sessioncache = self._get_cache()
            ttl = sessioncache.ttl(self.cache_key)
            return timezone.now() + timedelta(seconds=ttl)
        except:
            return None
    

    @property
    def idpid(self):
        idpid = self.get("idp") 
        if idpid:
            return idpid
        elif self._idppk:
            idp = models.IdentityProvider.get_idp(self._idppk)
            if idp:
                return idp.idp
            else:
                return None

    def flush(self):
        self.expired_session_key = None
        super().flush()

    def is_empty(self):
        if self.expired_session_key:
            return False
        else:
            return super().is_empty()

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

    def get_session_age(self):
        try:
            timeout = self._session_cache.get("session_timeout")
            if timeout:
                return timeout
        except:
            pass

        if self.get(USER_SESSION_KEY):
            return settings.SESSION_AGE
        else:
            return settings.GUEST_SESSION_AGE

    def get_expiry_age(self, **kwargs):
        return self.get_session_cookie_age()

    def get_cache_key(self,session_key=None):
        if not session_key:
            session_key = self.session_key
        return self.cache_key_prefix + session_key


    def load(self):
        try:
            sessioncache = self._get_cache()
            cachekey = self.cache_key
            session_data = sessioncache.get(cachekey)
            timeout = session_data.get("session_timeout")
            if timeout and session_data.get(USER_SESSION_KEY):
                try:
                    sessioncache.expire(cachekey,timeout)
                except:
                    pass
        except Exception:
            # Some backends (e.g. memcache) raise an exception on invalid
            # cache keys. If this happens, reset the session. See #17810.
            session_data = None
        if session_data is not None:
            return session_data

        if self._session_key and "-" in self._session_key:
            #this is a authenticated session key
            self.expired_session_key = self._session_key
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
                      self.get_session_age())
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
            idpid = self.get("idp")
            if idpid:
                idp = models.IdentityProvider.get_idp(idpid)
                idpid = convert_decimal(idp.id,36)
            while True:
                if idpid:
                    session_key = "{3}-{1}{0}{2}".format(self._get_process_prefix(),get_random_string(16, VALID_KEY_CHARS),get_random_string(16, VALID_KEY_CHARS),idpid)
                else:
                    session_key = "{1}{0}{2}".format(self._get_process_prefix(),get_random_string(16, VALID_KEY_CHARS),get_random_string(16, VALID_KEY_CHARS))

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
            idpid = self.get("idp")
            if idpid:
                idp = models.IdentityProvider.get_idp(idpid)
                idpid = convert_decimal(idp.id,36)
            try:
                while True:
                    if idp:
                        session_key = "{3}-{1}{0}{2}".format(prefix,get_random_string(16, VALID_KEY_CHARS),get_random_string(16, VALID_KEY_CHARS),idpid)
                    else:
                        session_key = "{1}{0}{2}".format(prefix,get_random_string(16, VALID_KEY_CHARS),get_random_string(16, VALID_KEY_CHARS))

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


