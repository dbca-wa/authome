import logging

from django.core.exceptions import PermissionDenied
from django.conf import settings

from social_core.backends import azuread_b2c
from social_core.exceptions import AuthException

from .models import IdentityProvider

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
        idp = request.COOKIES.get(settings.PREFERED_IDP_COOKIE_NAME,None)
        policy = IdentityProvider.get_userflow(idp)

        if not policy or not policy.lower().startswith('b2c_'):
            raise AuthException('SOCIAL_AUTH_AZUREAD_B2C_OAUTH2_POLICY is '
                                'required and should start with `b2c_`')

        logger.debug("Prefered idp is '{}', Choosed userflow is '{}'".format(idp,policy))
        return policy

    @property
    def base_url(self):
        return self.setting('BASE_URL').format(self.policy)

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
            raise PermissionDenied("{}:{}".format(ex.__class__.__name__,str(ex)))

