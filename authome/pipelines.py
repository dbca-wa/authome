import logging

from django.core.exceptions import PermissionDenied

from .models import IdentityProvider

logger = logging.getLogger(__name__)

def associate_idp(backend, uid, user=None, *args, **kwargs):
    idp = kwargs['response']['idp']
    idp_obj,created = IdentityProvider.objects.get_or_create(idp=idp)
    logger.debug("authenticate the user({}) with identity provider({}={})".format(user.email if user else "",idp_obj.name,idp))
    if idp_obj.name:
        backend.strategy.session_set("idp", idp_obj.name)

    
def set_backend_logout_url(backend, uid, user=None, *args, **kwargs):
    logger.debug("set backend logout url to {}".format(backend.logout_url))
    backend.strategy.session_set("backend_logout_url", backend.logout_url)
