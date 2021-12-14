import logging
import urllib.parse

from django.core.exceptions import PermissionDenied
from django.utils.http import urlencode
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import login, logout
from django.http import HttpResponseForbidden,HttpResponseRedirect
from django.contrib.auth import REDIRECT_FIELD_NAME

from .models import IdentityProvider,UserGroup
from .views import signout, get_post_b2c_logout_url
from .utils import get_usercache

logger = logging.getLogger(__name__)

usercache = get_usercache()

def email_lowercase(backend,details, user=None,*args, **kwargs):
    """
    A pipeline to turn the email address to lowercase
    """
    email = details.get("email")
    details['email'] = email.strip().lower() if email else None

    return {"details":details}

_max_age = 100 * 365 * 24 * 60 * 60
def check_idp_and_usergroup(backend,details, user=None,*args, **kwargs):
    request = backend.strategy.request

    logger.debug("Data returned from B2C.\n{}".format( "\n".join( sorted(["{} = {}".format(k,v) for k,v in kwargs['response'].items()]) )))

    email = details.get("email")

    #reset is_staff and is_superuser property based on user category.
    if email:
        dbcagroup = UserGroup.dbca_group()
        usergroups = UserGroup.find_groups(email)[0]
        if any(group.is_group(dbcagroup) for group in usergroups ):
            details["is_staff"] = True
            if not user:
                details["is_superuser"] = False
        else:
            details["is_staff"] = False
            details["is_superuser"] = False

    if hasattr(request,"policy"):
        #not a sign in request
        return

    #get the identityprovider from b2c response
    idp = kwargs['response'].get("idp",IdentityProvider.LOCAL_PROVIDER)
    idp_obj,created = IdentityProvider.objects.get_or_create(idp=idp)
    logger.debug("authenticate the user({}) with identity provider({}={})".format(email,idp_obj.idp,idp))

    #get backend logout url
    backend_logout_url = backend.logout_url if hasattr(backend,"logout_url") else settings.BACKEND_LOGOUT_URL

    if user and not user.is_active:
        #use is inactive, automatically logout 
        logout(request)
        logout_url = backend_logout_url.format(get_post_b2c_logout_url(request,idp_obj))
        logger.debug("Redirect to '{}' to logout from identity provider".format(logout_url))
        response = signout(request,logout_url=logout_url,message="Your account was disabled.")
        return response

    #check whether identity provider is the same as the configured identity provider
    if email:
        configed_idp_obj = UserGroup.get_identity_provider(email)
        if configed_idp_obj and configed_idp_obj != idp_obj:
            #The idp used for user authentication is not the idp configured in UserGroup, automatically logou
            logger.debug("The user({}) shoule authenticate with '{}' instead of '{}'".format(email,configed_idp_obj,idp_obj))
            logout(request)
            logout_url = backend_logout_url.format(get_post_b2c_logout_url(request,idp_obj))
            logger.debug("Redirect to '{}' to logout from identity provider".format(logout_url))
            response = signout(request,logout_url=logout_url,message="You can only sign in through identity provider '{}'".format(configed_idp_obj))

            #set the prefer IdentityProvider
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

    backend.strategy.session_set("idp", idp_obj.idp)

    details["last_idp"] = idp_obj

    logger.debug("set backend logout url to {}".format(backend_logout_url))
    backend.strategy.session_set("backend_logout_url",backend_logout_url)


def user_details(strategy, details, user=None, *args, **kwargs):
    """Update user details using data from provider."""
    if not user:
        return

    changed = False  # flag to track changes
    protected = ('username', 'id', 'pk', 'email') + \
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
        if current_value == value:
            continue

        changed = True
        logger.debug("The {1} of the User({0}) was changed from {2} to {3}".format(user.email,name,current_value,value))
        setattr(user, name, value)

    if not user.first_name or not user.last_name:
        nexturl = strategy.request.session[REDIRECT_FIELD_NAME]
        if nexturl:
            nexturl = "/sso/profile/edit?{}={}".format(REDIRECT_FIELD_NAME,urllib.parse.quote(nexturl))
        else:
            nexturl = "/sso/profile/edit"
        strategy.request.session[REDIRECT_FIELD_NAME] = nexturl

    if changed:
        strategy.storage.user.changed(user)
        if usercache:
            usercache.set(settings.GET_USER_KEY(user.id),user,settings.USER_CACHE_TIMEOUT)
            logger.debug("Cache the user({}) data to usercache".format(user.email))
