import time
import logging
from importlib import import_module

from django.conf import settings
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.exceptions import SessionInterrupted
from django.utils.cache import patch_vary_headers
from django.utils.deprecation import MiddlewareMixin
from django.utils.http import http_date
from django.http import HttpResponse,HttpResponseForbidden

logger = logging.getLogger(__name__)

FORBIDDEN_RESPONSE = HttpResponseForbidden()

class ClusterSessionMiddleware(MiddlewareMixin):
    def __init__(self, get_response=None):
        super().__init__(get_response)
        engine = import_module(settings.SESSION_ENGINE)
        self.SessionStore = engine.SessionStore

    def process_request(self, request):
        session_cookie = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        if session_cookie:
            values = session_cookie.split("|")
            if len(values) == 1:
                session_key = values[0]
                lb_hash_key = request.headers.get("x-hash-key")
                if not lb_hash_key:
                    return HttpResponse("Can't find x-hash-key",status=500)
                request.session = self.SessionStore(lb_hash_key,None,session_key)
            else:
                try:
                    lb_hash_key,auth2_clusterid,session_key = values
                    if auth2_clusterid != settings.AUTH2_CLUSTERID:
                        #current auth2 server is not the original auth2 server
                        #maybe caused by new auth2 server added, existing auth2 server removed, some auth2 server unavailable, or hacked by the user
                        if not self.SessionStore.check_integrity(lb_hash_key,auth2_clusterid,session_key):
                            #session cookie is hacked by the user or 
                            return FORBIDDEN_RESPONSE
                
                    request.session = self.SessionStore(lb_hash_key,auth2_clusterid,session_key)
                except:
                    #invalid session cookie
                    request.session = self.SessionStore(None,None,None)
        else:
            lb_hash_key = request.headers.get("x-hash-key")
            if not lb_hash_key:
                if request.path.startswith("/cluster"):
                    request.session = self.SessionStore(None,None,None)
                else:
                    return HttpResponse("Can't find x-hash-key",status=500)
            request.session = self.SessionStore(lb_hash_key,settings.AUTH2_CLUSTERID,None)

    def process_response(self, request, response):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie or delete
        the session cookie if the session has been emptied.
        """
        try:
            accessed = request.session.accessed
            modified = request.session.modified
            empty = request.session.is_empty()
        except AttributeError:
            return response
        # First check if we need to delete this cookie.
        # The session should be deleted only if the session is entirely empty.
        if empty:
            if settings.SESSION_COOKIE_NAME in request.COOKIES:
                response.delete_cookie(
                    settings.SESSION_COOKIE_NAME,
                    path=settings.SESSION_COOKIE_PATH,
                    domain=settings.SESSION_COOKIE_DOMAIN,
                    samesite=settings.SESSION_COOKIE_SAMESITE,
                )
                patch_vary_headers(response, ('Cookie',))
        else:
            if accessed:
                patch_vary_headers(response, ('Cookie',))

            if response.status_code != 500 and (modified or settings.SESSION_SAVE_EVERY_REQUEST):
                try:
                    request.session.save()
                except UpdateError:
                    raise SessionInterrupted(
                        "The request's session was deleted before the "
                        "request completed. The user may have logged "
                        "out in a concurrent request, for example."
                    )

            if request.session.cookie_changed :
                logger.debug("Return a session cookie '{}...' in response".format(request.session.cookie_value[:-10]))
                if request.session.get_expire_at_browser_close():
                    max_age = None
                    expires = None
                else:
                    max_age = request.session.get_expiry_age()
                    expires_time = time.time() + max_age
                    expires = http_date(expires_time)

                response.set_cookie(
                    settings.SESSION_COOKIE_NAME,
                    request.session.cookie_value, max_age=max_age,
                    expires=expires, domain=settings.SESSION_COOKIE_DOMAIN,
                    path=settings.SESSION_COOKIE_PATH,
                    secure=settings.SESSION_COOKIE_SECURE or None,
                    httponly=settings.SESSION_COOKIE_HTTPONLY or None,
                    samesite=settings.SESSION_COOKIE_SAMESITE,
                )
        return response

