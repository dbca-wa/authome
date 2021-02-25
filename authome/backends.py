import logging
import urllib.parse
import re

from django.core.exceptions import PermissionDenied
from django.conf import settings

from social_core.backends import azuread_b2c
from social_core.exceptions import AuthException

from .models import IdentityProvider,CustomizableUserflow,User
from .utils import get_redirect_domain
from .exceptions import AzureADB2CAuthenticateFailed

logger = logging.getLogger(__name__)

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
            domain = get_redirect_domain(request)
            userflow = CustomizableUserflow.get_userflow(domain)
            if userflow.fixed:
                policy = userflow.fixed
            elif not domain:
                policy = userflow.default
            else:
                idp = request.COOKIES.get(settings.PREFERED_IDP_COOKIE_NAME,None)
                idp = IdentityProvider.get_idp(idp)
                if idp and idp.userflow:
                    if idp == IdentityProvider.LOCAL_PROVIDER:
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
        return "{}/{}".format(self.setting('BASE_URL'),self.policy)
        if self.policy.startswith("B2C_1_"):
            return "{}/{}".format(self.setting('BASE_URL'),self.policy)
        else:
            return self.setting('BASE_URL')

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

    error_re = re.compile("^\s*(?P<code>[A-Z0-9]+)\s*:")
    def process_error(self, data):
        try:
            super().process_error(data)
        except Exception as ex:
            error = self.strategy.request.GET.get("error_description")
            error_code = None
            if error:
                m = self.error_re.search(error)
                if m:
                    error_code = m.group('code')
            if hasattr(self.strategy.request,"http_error_code"):
                raise AzureADB2CAuthenticateFailed(self.strategy.request.http_error_code,error_code,self.strategy.request.http_error_message,ex)
            else:
                raise AzureADB2CAuthenticateFailed(400,error_code,"Failed to authenticate the user.{}",ex)

