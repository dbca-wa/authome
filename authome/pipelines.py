import logging

from django.core.exceptions import PermissionDenied
from django.utils.http import urlencode
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import login, logout
from django.http import HttpResponseForbidden,HttpResponseRedirect

from .models import IdentityProvider,UserGroup
from .views import signout, get_post_logout_url

logger = logging.getLogger(__name__)

_max_age = 100 * 365 * 24 * 60 * 60
def check_idp_and_usergroup(backend,details, user=None,*args, **kwargs):
    request = backend.strategy.request

    idp = kwargs['response']['idp']
    idp_obj,created = IdentityProvider.objects.get_or_create(idp=idp)
    logger.debug("authenticate the user({}) with identity provider({}={})".format(details.get("email"),idp_obj.idp,idp))

    backend_logout_url = backend.logout_url if hasattr(backend,"logout_url") else settings.BACKEND_LOGOUT_URL

    if user and not user.is_active:
        logout(request)
        logout_url = backend_logout_url.format(get_post_logout_url(request,idp_obj))
        logger.debug("Redirect to '{}' to logout from identity provider".format(logout_url))
        response = signout(request,logout_url=logout_url,message="Your account was disabled.")
        return response

    email = details.get("email")
    #check whether identity provider is the same as the configured identity provider
    if email:
        configed_idp_obj = UserGroup.get_identity_provider(email)
        if configed_idp_obj and configed_idp_obj != idp_obj:
            logger.debug("The user({}) shoule authenticate with '{}' instead of '{}'".format(email,configed_idp_obj,idp_obj))
            logout(request)
            logout_url = backend_logout_url.format(get_post_logout_url(request,idp_obj))
            logger.debug("Redirect to '{}' to logout from identity provider".format(logout_url))
            response = signout(request,logout_url=logout_url,message="You can only sign in through identity provider '{}'".format(configed_idp_obj))

            response.set_cookie(
                settings.PREFERED_IDP_COOKIE_NAME,
                configed_idp_obj.idp,
                httponly=True,
                path="/sso/",
                max_age=_max_age,
                samesite=None
            )
            #clear the session
            request.session.flush()
            return response

    #get the user category which is the child of the public group,
    usergroup = None
    for category in UserGroup.usercategories():
        if category[0].contain(email):
            usergroup = category[0]
            break;

    if not usergroup:
        logout(request)
        logout_url = backend_logout_url.format(get_post_logout_url(request,idp_obj))
        logger.debug("Redirect to '{}' to logout from identity provider".format(logout_url))
        message = "You are not belonging to any user category."
        response = signout(request,logout_url=logout_url,message=message)

        request.session.flush()
        return response

    dbca_group = UserGroup.dbca_group()
    #the user group must match the signup user category if user already exists, otherwise, only dbca staff is allowed.
    if (user and usergroup != user.usergroup) or (not user and usergroup != dbca_group):
        logout(request)
        logout_url = backend_logout_url.format(get_post_logout_url(request,idp_obj))
        logger.debug("Redirect to '{}' to logout from identity provider".format(logout_url))
        if not user:
            message = "You are not registered, please register first."
        elif usergroup:
            message = "You have been moved from category '{1}' to category '{0}', please register to category '{0}' first.".format(usergroup or UserGroup.public_group(),user.usergroup)
        else:
            message = "You have been removed from category '{1}'.".format(usergroup or UserGroup.public_group(),user.usergroup)
        response = signout(request,logout_url=logout_url,message=message)

        request.session.flush()
        return response
    #reset is_staff and is_superuser property based on user category.
    if usergroup == dbca_group:
        details["is_staff"] = True
        if not user:
            details["is_superuser"] = False
    else:
        details["is_staff"] = False
        details["is_superuser"] = False
    details["usergroup"] = usergroup
    details["username"] = email

    backend.strategy.session_set("idp", idp_obj.idp)

    details["last_idp"] = idp_obj

    logger.debug("set backend logout url to {}".format(backend_logout_url))
    backend.strategy.session_set("backend_logout_url",backend_logout_url)

    return {"username":email}

