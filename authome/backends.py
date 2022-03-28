import logging
import urllib.parse
import re

from django.conf import settings
from django.urls import reverse

from social_core.backends import azuread_b2c
from social_core.exceptions import AuthException

from .models import IdentityProvider, CustomizableUserflow
from .utils import get_redirect_domain
from .exceptions import AzureADB2CAuthenticateFailed

logger = logging.getLogger(__name__)


class AzureADB2COAuth2(azuread_b2c.AzureADB2COAuth2):
    AUTHORIZATION_URL = '{base_url}/oauth2/v2.0/authorize'
    OPENID_CONFIGURATION_URL = '{base_url}/v2.0/.well-known/openid-configuration'
    ACCESS_TOKEN_URL = '{base_url}/oauth2/v2.0/token'
    JWKS_URL = '{base_url}/discovery/v2.0/keys'
    LOGOUT_URL = '{base_url}/oauth2/v2.0/logout?post_logout_redirect_uri={{}}'

    def  __init__(self,*args,**kwargs):
        self.switch_auth_url()
        super().__init__(*args,**kwargs)

    @property
    def policy(self):
        request = self.strategy.request
        if request and hasattr(request,"policy"):
            policy = request.policy
        else:
            domain = get_redirect_domain(request) if request else None
            userflow = CustomizableUserflow.get_userflow(domain)
            if userflow.fixed:
                logger.debug("Use the fixed userflow({1}.{2}) for domain({0})".format(domain,userflow.domain,userflow.fixed))
                policy = userflow.fixed
            elif not domain:
                logger.debug("Use the default userflow({1}.{2}) for domain({0})".format(domain,userflow.domain,userflow.default))
                policy = userflow.default
            else:
                idpid = request.COOKIES.get(settings.PREFERED_IDP_COOKIE_NAME,None) if request else None
                idp = IdentityProvider.get_idp(idpid) if idpid else None
                if idp and idp.userflow:
                    policy = idp.userflow
                else:
                    policy = userflow.default

                logger.debug("Prefered idp is '{}', Choosed userflow is '{}', request domain is '{}' ".format(idp,policy,domain))

        if not policy or not policy.lower().startswith('b2c_'):
            raise AuthException('SOCIAL_AUTH_AZUREAD_B2C_OAUTH2_POLICY is '
                                'required and should start with `b2c_`')

        return policy

    @property
    def base_url(self):
        return "{}/{}".format(self.setting('BASE_URL'),self.policy)
        """
        if self.policy.startswith("B2C_1_"):
            return "{}/{}".format(self.setting('BASE_URL'),self.policy)
        else:
            return self.setting('BASE_URL')
        """

    _default_logout_url = None
    @classmethod
    def get_logout_url(cls):
        if not cls._default_logout_url:
            cls._default_logout_url = cls().logout_url

        return cls._default_logout_url


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
                raise AzureADB2CAuthenticateFailed(self.strategy.request,self.strategy.request.http_error_code,error_code,self.strategy.request.http_error_message,ex)
            else:
                raise AzureADB2CAuthenticateFailed(self.strategy.request,400,error_code,"Failed to authenticate the user.{}",ex)

    _auth_local_url = reverse("auth_local")
    def auth_local_url(self):
        return self._auth_local_url

    def switch_auth_url(self):
        if settings.SWITCH_TO_AUTH_LOCAL:
            self.auth_url = self.auth_local_url
        else:
            self.auth_url = super().auth_url
