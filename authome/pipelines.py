import logging
import urllib.parse

from django.core.exceptions import PermissionDenied
from django.utils.http import urlencode
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import login, logout
from django.http import HttpResponseForbidden,HttpResponseRedirect
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.urls import reverse

from .models import IdentityProvider,UserGroup,can_access
from .views import signout
from .cache import get_usercache
from . import utils
from . import exceptions

logger = logging.getLogger(__name__)


_profile_edit_url = None
def profile_edit_url():
    global _profile_edit_url
    if not _profile_edit_url:
        _profile_edit_url = reverse("selfservice:profile_edit")
    return _profile_edit_url

def email_lowercase(backend,details, user=None,*args, **kwargs):
    """
    A pipeline to turn the email address to lowercase
    """
    email = details.get("email")
    if email:
        details['email'] = email.strip().lower()

    return {"details":details}

_max_age = 100 * 365 * 24 * 60 * 60
def check_idp_and_usergroup(backend,details, user=None,*args, **kwargs):
    request = backend.strategy.request

    logger.debug("Data returned from B2C.\n{}".format( "\n".join( sorted(["{} = {}".format(k,v) for k,v in kwargs['response'].items()]) )))

    email = details.get("email")

    #reset is_staff and is_superuser property based on user category.
    usergroups = None
    if email:
        dbcagroup = UserGroup.dbca_group()
        usergroups = UserGroup.find_groups(email)[0]
        if any(group.is_group(dbcagroup) for group in usergroups ):
            details["is_staff"] = True
            #set is_superuser based on whether the user can access module '/admin'
            details["is_superuser"] = can_access(email,settings.AUTH2_DOMAIN,"/admin/")
        else:
            details["is_staff"] = False
            details["is_superuser"] = False

    if hasattr(request,"policy"):
        #not a sign in request
        mfa_method = kwargs['response'].get("mfaMethod")
        if mfa_method and request.session.get("mfa_method") and request.session.get("mfa_method") != mfa_method:
            #mfa was changed, update the user session 
            request.session["mfa_method"] = mfa_method
        return

    #get the identityprovider from b2c response
    idp = kwargs['response'].get("idp",IdentityProvider.LOCAL_PROVIDER)
    idp_obj,created = IdentityProvider.objects.get_or_create(idp=idp)
    logger.debug("authenticate the user({}) with identity provider({}={})".format(email,idp_obj.idp,idp))

    #get backend logout url
    if user and not user.is_active:
        #use is inactive, automatically logout 
        logger.debug("User({}) is inactive, automatically logout ".format(email))
        response = signout(request,idp=idp_obj,message="Your account is disabled.")
        return response

    #check whether identity provider is the same as the configured identity provider
    if email:
        configed_idp_obj = UserGroup.get_identity_provider(email)
        if configed_idp_obj and configed_idp_obj != idp_obj:
            #The idp used for user authentication is not the idp configured in UserGroup, automatically logou
            logger.debug("The user({}) must authenticate with '{}' instead of '{}', automatically logout".format(email,configed_idp_obj,idp_obj))
            response = signout(request,idp=idp_obj,message="You can only sign in with social media '{}'".format(configed_idp_obj))

            #set the prefer IdentityProvider
            response.set_cookie(
                settings.PREFERED_IDP_COOKIE_NAME,
                configed_idp_obj.idp,
                httponly=True,
                path="/sso/",
                max_age=_max_age,
                samesite=None
            )
            return response

    backend.strategy.session_set("idp", idp_obj.idp)

    details["last_idp"] = idp_obj
    if idp_obj.idp == "local":
        mfa_method = kwargs['response'].get("mfaMethod")
        if mfa_method:
            backend.strategy.session_set("mfa_method",mfa_method)
            logger.debug("MFA Method is '{}'".format(mfa_method))


    if usergroups:
        timeout = UserGroup.get_session_timeout(usergroups)
        if timeout:
            backend.strategy.session_set("session_timeout",timeout)
            pass


def user_details(strategy, details, user=None, *args, **kwargs):
    """Update user details using data from provider."""
    if not user:
        return

    changed = False  # flag to track changes
    protected = ('username', 'id', 'pk', 'email','first_name','last_name') + \
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
        nexturl = strategy.request.session.get(REDIRECT_FIELD_NAME)
        if nexturl:
            nexturl_parsed = utils.parse_url(nexturl)
            if nexturl_parsed["path"] != profile_edit_url():
                nexturl = "{}?{}={}".format(profile_edit_url(),REDIRECT_FIELD_NAME,urllib.parse.quote(nexturl))
        else:
            nexturl = profile_edit_url()
        strategy.request.session[REDIRECT_FIELD_NAME] = nexturl

    if changed:
        strategy.storage.user.changed(user)
    
    #save the user to cache if user is changed or in multiple cluster env.
    usercache = get_usercache(user.id)
    if usercache:
        usercache.set(settings.GET_USER_KEY(user.id),user,settings.STAFF_CACHE_TIMEOUT if user.is_staff else settings.USER_CACHE_TIMEOUT)

        
