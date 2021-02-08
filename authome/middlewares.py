import logging
import re

from django.utils.deprecation import MiddlewareMixin
from django.conf  import settings
from django.http import HttpResponseForbidden,HttpResponseRedirect
from django.contrib.auth import login, logout

from .models import UserGroup,IdentityProvider

logger = logging.getLogger(__name__)

_max_age = 100 * 365 * 24 * 60 * 60
class PreferedIDPMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        if request.path.startswith("/sso/complete/") and request.user.is_authenticated :
            res_idp = request.session.get("idp",None)
            if res_idp:
                req_idp = request.COOKIES.get(settings.PREFERED_IDP_COOKIE_NAME,None)
                if req_idp != res_idp :
                    response.set_cookie(
                        settings.PREFERED_IDP_COOKIE_NAME,
                        res_idp,
                        httponly=True,
                        secure=True,
                        path="/sso/",
                        max_age=_max_age,
                        samesite='lax'
                    )
            else:
                response.delete_cookie(
                    settings.PREFERED_IDP_COOKIE_NAME,
                    path="/sso/",
                    samesite='lax'
                )

        return response
