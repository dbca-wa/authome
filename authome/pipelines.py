import logging

from django.core.exceptions import PermissionDenied
from django.utils.http import urlencode
from django.conf import settings

from .models import IdentityProvider

logger = logging.getLogger(__name__)

def associate_idp(backend, uid, user=None, *args, **kwargs):
    idp = kwargs['response']['idp']
    idp_obj,created = IdentityProvider.objects.get_or_create(idp=idp)
    logger.debug("authenticate the user({}) with identity provider({}={})".format(user.email if user else "",idp_obj.name,idp))
    if idp_obj.name:
        backend.strategy.session_set("idp", idp_obj.name)
    
    backend_logout_url = backend.logout_url if hasattr(backend,"logout_url") else None
    if backend_logout_url:
        if idp_obj.logout_url:
            post_logout_url = idp_obj.logout_url.format("https://{}/static/signout.html".format(backend.strategy.request.get_host()))
        else:
            post_logout_url = "https://{}/static/signout.html".format(backend.strategy.request.get_host())

        params = {"post_logout_redirect_uri":post_logout_url}

        if "?" in backend_logout_url:
            logout_url = "{}&{}".format(backend_logout_url,urlencode(params))
        else:
            logout_url = "{}?{}".format(backend_logout_url,urlencode(params))
    else:
        logout_url = settings.BACKEND_LOGOUT_URL or "https://{}/static/signout.html".format(backend.strategy.request.get_host())

    logger.debug("set backend logout url to {}".format(logout_url))
    backend.strategy.session_set("backend_logout_url",logout_url)
