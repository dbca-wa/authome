import logging
import urllib.parse
import re

from django.conf import settings
from django.urls import reverse

from social_core.backends import azuread_b2c
from social_core.exceptions import AuthException

from .models import IdentityProvider, CustomizableUserflow
from . import utils
from .exceptions import AzureADB2CAuthenticateFailed,PolicyNotConfiguredException

logger = logging.getLogger(__name__)


class AzureADB2COAuth2(azuread_b2c.AzureADB2COAuth2):
    AUTHORIZATION_URL = '{base_url}/oauth2/v2.0/authorize'
    OPENID_CONFIGURATION_URL = '{base_url}/v2.0/.well-known/openid-configuration'
    ACCESS_TOKEN_URL = '{base_url}/oauth2/v2.0/token'
    JWKS_URL = '{base_url}/discovery/v2.0/keys'
    LOGOUT_URL = '{base_url}/oauth2/v2.0/logout?post_logout_redirect_uri={{}}'

    def  __init__(self,strategy=None,redirect_uri=None,*args,**kwargs):
        if redirect_uri and not redirect_uri.startswith("https"):
            #because auth2 backend is running with client domain instead of auth2 domain, but only auth2 is registered in azure b2c
            #we should manually build the redirect_uri with auth2_domain
            if redirect_uri.startswith("/"):
                redirect_uri = "https://{}{}".format(settings.AUTH2_DOMAIN,redirect_uri)
            else:
                redirect_uri = "https://{}/{}".format(settings.AUTH2_DOMAIN,redirect_uri)
        #Switch auth_local between azure b2c and auth_local
        self.switch_auth_url()
        super().__init__(strategy=strategy,redirect_uri=redirect_uri,*args,**kwargs)

    @property
    def policy(self):
        request = self.strategy.request
        if request and hasattr(request,"policy"):
            #if request has a property policy, use that policy directly,
            #The features(mfa set, mfa reset, and password reset) use this proerty 'policy' to specific the customized policy
            policy = request.policy
            if not policy:
                raise PolicyNotConfiguredException('ADB2C policy is not configured for request({})'.format(request.path))
            elif not policy.lower().startswith('b2c_'):
                raise PolicyNotConfiguredException('The name of ADB2C policy({}) should be started with "b2c_" case-insensitive.'.format(policy))
        else:
            domain = (utils.get_domain(request.session.get(utils.REDIRECT_FIELD_NAME)) or request.get_host()) if request else None
            if not domain or domain == settings.AUTH2_DOMAIN:
                #Domain is None or dmain is auth2, use the user flow's default policy
                userflow = CustomizableUserflow.get_userflow(None)
                logger.debug("Use the default userflow({1}.{2}) for domain({0})".format(domain,userflow.domain,userflow.default))
                policy = userflow.default
            else:
                userflow = CustomizableUserflow.get_userflow(domain)
                if userflow.fixed:
                    #A fixed policy is configured for the domain related userflow, use it directly
                    logger.debug("Use the fixed userflow({1}.{2}) for domain({0})".format(domain,userflow.domain,userflow.fixed))
                    policy = userflow.fixed
                else:
                    #if the cookie 'PREFERED_IDP_COOKIE' exists, and try to get the policy from the latest used idp
                    idpid = request.COOKIES.get(settings.PREFERED_IDP_COOKIE_NAME,None) if request else None
                    idp = IdentityProvider.get_idp(idpid) if idpid else None
                    if idp and idp.userflow:
                        #Found the latest used idp, and that idp has a configued user flow, use the user flow directly
                        policy = idp.userflow
                    else:
                        #Can't find the latest used idp, user the domain related userflow's default policy
                        policy = userflow.default

                    logger.debug("Prefered idp is '{}', Choosed userflow is '{}', request domain is '{}' ".format(idp,policy,domain))
            if not policy:
                raise PolicyNotConfiguredException('ADB2C policy is not configured for domain({})'.format(domain))
            elif not policy.lower().startswith('b2c_'):
                raise PolicyNotConfiguredException('The name of ADB2C policy({}) should be started with "b2c_" case-insensitive.'.format(policy))

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

    error_re = re.compile("^\\s*(?P<code>[A-Z0-9]+)\\s*:")
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
        """
        Return url of auth_local
        """
        return self._auth_local_url

    def switch_auth_url(self):
        """
        swith authentication between azure b2c and auth_local based on setting 'SWITCH_TO_AUTH_LOCAL'
        """
        if settings.SWITCH_TO_AUTH_LOCAL:
            self.auth_url = self.auth_local_url
        else:
            self.auth_url = super().auth_url
