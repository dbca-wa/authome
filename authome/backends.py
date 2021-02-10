import logging
import urllib.parse

from django.core.exceptions import PermissionDenied
from django.conf import settings
from django.core.exceptions import SuspiciousOperation

from social_core.backends import azuread_b2c
from social_core.exceptions import AuthException

from .models import IdentityProvider,CustomizableUserflow,User
from .utils import get_clientapp_domain,get_usercache

logger = logging.getLogger(__name__)

usercache = get_usercache()

class AuthenticateFailed(SuspiciousOperation): 
    def __init__(self,http_code,message,ex):
        super().__init__(message.format(str(ex)))
        self.http_code = http_code
        self.ex = ex

class AzureADB2COAuth2(azuread_b2c.AzureADB2COAuth2):
    AUTHORIZATION_URL = '{base_url}/oauth2/v2.0/authorize'
    OPENID_CONFIGURATION_URL = '{base_url}/v2.0/.well-known/openid-configuration'
    ACCESS_TOKEN_URL = '{base_url}/oauth2/v2.0/token'
    JWKS_URL = '{base_url}/discovery/v2.0/keys'
    LOGOUT_URL = '{base_url}/oauth2/v2.0/logout?post_logout_redirect_uri={{}}'

    @property
    def policy(self):
        request = self.strategy.request
        if hasattr(request,"policy"):
            policy = request.policy
        else:
            domain = get_clientapp_domain(request)
            userflow = CustomizableUserflow.get_userflow(domain)
            if userflow.fixed:
                policy = userflow.fixed
            elif not domain:
                policy = userflow.default
            else:
                idp = request.COOKIES.get(settings.PREFERED_IDP_COOKIE_NAME,None)
                idp = IdentityProvider.get_idp(idp)
                if idp and idp.userflow:
                    if idp == IdentityProvider.EMAIL_PROVIDER:
                        policy = userflow.email
                    else:
                        policy = idp.userflow
                else:
                    policy = userflow.default

                logger.debug("Prefered idp is '{}', Choosed userflow is '{}'".format(idp,policy))

        if not policy or not policy.lower().startswith('b2c_'):
            raise AuthException('SOCIAL_AUTH_AZUREAD_B2C_OAUTH2_POLICY is '
                                'required and should start with `b2c_`')

        return policy

    @property
    def base_url(self):
        return self.setting('BASE_URL').format(self.policy)

    def get_profile_edit_url(self,next_url,policy='B2C_1_email_profile'):
        return "{base_url}/oauth2/v2.0/authorize?client_id={client_id}&redirect_uri={next_url}&scope=openid+email&response_type=code".format(
            base_url=self.setting('BASE_URL').format(policy),
            client_id=self.setting('KEY'),
            next_url=urllib.parse.quote(next_url)
        )

    @property
    def logout_url(self):
        return self.LOGOUT_URL.format(base_url=self.base_url) 

    def auth_extra_arguments(self):
        """
        Return extra arguments needed on auth process.

        The defaults can be overridden by GET parameters.
        """
        extra_arguments = super(AzureADB2COAuth2, self).auth_extra_arguments()
        return extra_arguments

    def process_error(self, data):
        try:
            super().process_error(data)
        except Exception as ex:
            if hasattr(self.strategy.request,"http_error_code"):
                raise AuthenticateFailed(self.strategy.request.http_error_code,self.strategy.request.http_error_message,ex)
            else:
                raise AuthenticateFailed(400,"Failed to authenticate the user.{}",ex)

if usercache:
    def _get_cached_user(self,userid):
        userkey = settings.GET_USER_KEY(userid)
        user = usercache.get(userkey)
        if not user:
            user = User.objects.get(pk=userid)
            usercache.set(userkey,user,settings.USER_CACHE_TIMEOUT)
            logger.debug("Cache the user({}) data to usercache".format(user.email))
        else:
            logger.debug("Get the user({}) data from usercache".format(user.email))
            pass
        return user

    AzureADB2COAuth2.get_user = _get_cached_user

        
        

