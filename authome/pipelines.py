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
    else:
        details["is_staff"] = False
        details["is_superuser"] = False
    details["usergroup"] = usergroup

    backend.strategy.session_set("idp", idp_obj.idp)

    details["last_idp"] = idp_obj

    logger.debug("set backend logout url to {}".format(backend_logout_url))
    backend.strategy.session_set("backend_logout_url",backend_logout_url)


def user_details(strategy, details, user=None, *args, **kwargs):
    """Update user details using data from provider."""
    if not user:
        return

    changed = False  # flag to track changes
    protected = ( 'id', 'pk', 'email') + \
                tuple(strategy.setting('PROTECTED_USER_FIELDS', []))

    # Update user model attributes with the new data sent by the current
    # provider. Update on some attributes is disabled by default, for
    # example username and id fields. It's also possible to disable update
    # on fields defined in SOCIAL_AUTH_PROTECTED_USER_FIELDS.
    for name, value in details.items():
        if value is None or not hasattr(user, name) or name in protected:
            continue

        # Check https://github.com/omab/python-social-auth/issues/671
        current_value = getattr(user, name, None)
        if current_value and current_value == value:
            continue

        changed = True
        setattr(user, name, value)

    if changed:
        strategy.storage.user.changed(user)
