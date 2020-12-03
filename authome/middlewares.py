import logging
import re

from django.utils.deprecation import MiddlewareMixin
from django.conf  import settings
from django.http import HttpResponseForbidden,HttpResponseRedirect
from django.contrib.auth import login, logout

from .models import UserGroup,IdentityProvider

logger = logging.getLogger(__name__)

_url_re = re.compile("^((h|H)(t|T)(t|T)(p|P)(s|S)?://)?(?P<domain>[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*)(?P<path>/.*)$")
_max_age = 100 * 365 * 24 * 60 * 60
class PreferedIDPMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        if (request.path == "/" or request.path == ""):
            if not request.user.is_authenticated:
                idp = None
                next_url = request.GET.get("next")
                if next_url:
                    m = _url_re.match(next_url)
                    domain = m.group("domain") if m else None
                    if domain:
                        idp = IdentityProvider.get_idp_by_domain(domain)
                if idp:
                    req_idp = request.COOKIES.get(settings.PREFERED_IDP_COOKIE_NAME,None)
                    if req_idp != idp.idp :
                        response.set_cookie(
                            settings.PREFERED_IDP_COOKIE_NAME,
                            idp.idp,
                            httponly=True,
                            path="/sso/",
                            max_age=_max_age,
                            samesite=None
                        )
                elif not next_url:
                    response.delete_cookie(
                        settings.PREFERED_IDP_COOKIE_NAME,
                        path="/sso/",
                        samesite=None
                    )
        elif request.path.startswith("/sso/complete/") and request.user.is_authenticated :
            res_idp = request.session.get("idp",None)
            if res_idp:
                req_idp = request.COOKIES.get(settings.PREFERED_IDP_COOKIE_NAME,None)
                if req_idp != res_idp :
                    response.set_cookie(
                        settings.PREFERED_IDP_COOKIE_NAME,
                        res_idp,
                        httponly=True,
                        path="/sso/",
                        max_age=_max_age,
                        samesite=None
                    )
            else:
                response.delete_cookie(
                    settings.PREFERED_IDP_COOKIE_NAME,
                    path="/sso/",
                    samesite=None
                )

        return response
