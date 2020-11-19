import logging

from django.utils.deprecation import MiddlewareMixin
from django.conf  import settings
from django.http import HttpResponseForbidden,HttpResponseRedirect
from django.contrib.auth import login, logout

from .models import UserGroup

logger = logging.getLogger(__name__)

_max_age = 100 * 365 * 24 * 60 * 60
class PreferedIDPMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        if (request.path == "/" or request.path == "") and not request.GET.get('next', None):
            response.delete_cookie(
                settings.PREFERED_IDP_COOKIE_NAME,
                path="/sso/",
                samesite=None
            )
        elif request.path.startswith("/sso/complete/") and request.user.is_authenticated:
            res_idp = request.session.get("idp",None)
            if res_idp:
                email = request.user.email 
                configed_idp_obj = UserGroup.get_identity_provider(email)
                if configed_idp_obj and configed_idp_obj.name != res_idp:
                    logger.debug("The user({}) shoule authenticate with '{}' instead of '{}'".format(email,configed_idp_obj,res_idp))
                    backend_logout_url = request.session.get("backend_logout_url")
                    logout(request)
                    if backend_logout_url:
                        logger.debug("Redirect to '{}' to logout from identity provider".format(backend_logout_url))
                        response = HttpResponseRedirect("{}?post_logout_redirect_uri=https://{}/static/signout.html".format(backend_logout_url,request.get_host()))
                    else:
                        response = HttpResponseForbidden()
                    if configed_idp_obj.name:
                        response.set_cookie(
                            settings.PREFERED_IDP_COOKIE_NAME,
                            configed_idp_obj.name,
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
                    #clear the session
                    print("=========clear session")
                    request.session.flush()
                    print("session empty={}".format(request.session.is_empty()))
                else:
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
