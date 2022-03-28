import os

from .utils import env, get_digest_function
from datetime import timedelta
import dj_database_url

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEBUG = env('DEBUG', False)
LOGLEVEL = env('LOGLEVEL',default='WARNING')
if LOGLEVEL not in ["DEBUG",'INFO','WARNING','ERROR','CRITICAL']:
    LOGLEVEL = 'DEBUG' if DEBUG else 'INFO'

RELEASE = False if LOGLEVEL in ["DEBUG"] else True

SECRET_KEY = env('SECRET_KEY', 'PlaceholderSecretKey')
if not DEBUG:
    ALLOWED_HOSTS = env('ALLOWED_DOMAINS', '').split(',')
else:
    ALLOWED_HOSTS = ['*']
INTERNAL_IPS = ['127.0.0.1', '::1']
ROOT_URLCONF = 'authome.urls'
WSGI_APPLICATION = 'authome.wsgi.application'
AUTH_USER_MODEL = 'authome.User'

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django_extensions',
    'social_django',
    'authome',
]

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'authome.backends.AzureADB2COAuth2',
)
IGNORE_LOADING_ERROR = env('IGNORE_LOADING_ERROR',False)

EMAIL_HOST = env('EMAIL_HOST', default="")
EMAIL_PORT = env('EMAIL_PORT', 25)

AUTH2_DOMAIN = env("AUTH2_DOMAIN",default="auth2.dbca.wa.gov.au")

TOTP_SECRET_KEY_LENGTH = env("TOTP_SECRET_KEY_LENGTH",default=128)
TOTP_ISSUER = env("TOTP_ISSUER",default="DBCA")
TOTP_PREFIX = env("TOTP_PREFIX",default="DBCA")
TOTP_TIMESTEP = env("TOTP_TIMESTEP",default=30)
TOTP_VALIDWINDOW = env("TOTP_VALIDWINDOW",default=0)
TOTP_CHECK_LAST_CODE = env("TOTP_CHECK_LAST_CODE",default=True)
TOTP_DIGITS = env("TOTP_DIGITS",default=6)
TOTP_ALGORITHM = env("TOTP_ALGORITHM",default="SHA1")
TOTP_DIGEST = None

TOTP_ALGORITHM,TOTP_DIGEST = get_digest_function(TOTP_ALGORITHM)

# Azure AD settings
AZUREAD_AUTHORITY = env('AZUREAD_AUTHORITY', 'https://login.microsoftonline.com')
AZUREAD_RESOURCE = env('AZUREAD_RESOURCE', '00000002-0000-0000-c000-000000000000')

SOCIAL_AUTH_AZUREAD_B2C_OAUTH2_BASE_URL = env('AZUREAD_B2C_BASE_URL', 'baseurl')
SOCIAL_AUTH_AZUREAD_B2C_OAUTH2_KEY = env('AZUREAD_B2C_CLIENTID', 'clientid')
SOCIAL_AUTH_AZUREAD_B2C_OAUTH2_SECRET = env('AZUREAD_B2C_SECRETKEY', 'secret')
SOCIAL_AUTH_AZUREAD_B2C_OAUTH2_TENANT_ID = env('AZUREAD_B2C_TENANT_ID', 'tentid')
SOCIAL_AUTH_AZUREAD_B2C_OAUTH2_USER_FIELDS = env('AZUREAD_B2C_USER_FIELDS', default=["username","email","first_name","last_name","is_staff","is_superuser"])

SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = env('USERNAME_IS_FULL_EMAIL', default=True)
SOCIAL_AUTH_SLUGIFY_USERNAMES = env('SLUGIFY_USERNAMES', default=False)
SOCIAL_AUTH_CLEAN_USERNAMES = env('CLEAN_USERNAMES', default=False)
SOCIAL_AUTH_SANITIZE_REDIRECTS = False

SOCIAL_AUTH_REDIRECT_IS_HTTPS = True
SOCIAL_AUTH_TRAILING_SLASH = False
SOCIAL_AUTH_LOGIN_REDIRECT_URL = "/"
SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'authome.pipelines.email_lowercase',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.social_auth.associate_by_email',
    'authome.pipelines.check_idp_and_usergroup',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'authome.pipelines.user_details'
)
# set the domain-global session cookie
SESSION_COOKIE_DOMAIN = env('SESSION_COOKIE_DOMAIN', None)
if env('SESSION_COOKIE_NAME', None):
    SESSION_COOKIE_NAME = env('SESSION_COOKIE_NAME', None)
else:
    if SESSION_COOKIE_DOMAIN:
        SESSION_COOKIE_NAME = (SESSION_COOKIE_DOMAIN + ".sessionid").replace(".", "_")

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_HTTPONLY = env('SESSION_COOKIE_HTTPONLY', False)
SESSION_COOKIE_SECURE = env('SESSION_COOKIE_SECURE', False)
CSRF_COOKIE_SECURE = env('CSRF_COOKIE_SECURE', False)

GUEST_SESSION_AGE=env('GUEST_SESSION_AGE',default=3600) #login session timeout in seconds
SESSION_AGE=env('SESSION_AGE',default=1209600)
SESSION_COOKIE_AGE=SESSION_AGE * 2

SESSION_COOKIE_DOMAINS=env("SESSION_COOKIE_DOMAINS",default={})

def GET_SESSION_COOKIE_DOMAIN(domain):
    if domain.endswith(SESSION_COOKIE_DOMAIN):
        return  SESSION_COOKIE_DOMAIN
    else:
        for k,v in SESSION_COOKIE_DOMAINS.items():
            if domain.endswith(k):
                return v

        return None
        

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'authome.middlewares.PreferedIDPMiddleware'
]

# Internationalization
LANGUAGE_CODE = 'en-gb'
TIME_ZONE = 'Australia/Perth'
USE_I18N = False
USE_TZ = True
DATE_FORMAT = 'd M Y'
DATETIME_FORMAT = 'l d F Y, h:i A'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ['templates/'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


DATABASES = {
    # Defined in DATABASE_URL env variable.
    'default': dj_database_url.config(),
}

DATABASES['default']["CONN_MAX_AGE"] = 3600

# Static files configuration
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/sso/static/'
#STATICFILES_DIRS = (os.path.join(BASE_DIR, 'itassets', 'static'),)
AUTH_CACHE_SIZE=env("AUTH_CACHE_SIZE",default=2000)
if AUTH_CACHE_SIZE <= 0:
    AUTH_CACHE_SIZE = 2000

EMAIL_GROUPS_CACHE_SIZE=env("EMAIL_GROUPS_CACHE_SIZE",default=2000)
if EMAIL_GROUPS_CACHE_SIZE <= 0:
    EMAIL_GROUPS_CACHE_SIZE = 2000

PUBLIC_EMAIL_GROUPS_CACHE_SIZE=env("PUBLIC_EMAIL_GROUPS_CACHE_SIZE",default=500)
if PUBLIC_EMAIL_GROUPS_CACHE_SIZE <= 0:
    PUBLIC_EMAIL_GROUPS_CACHE_SIZE = 500

BASIC_AUTH_CACHE_SIZE=env("BASIC_AUTH_CACHE_SIZE",default=1000)
if BASIC_AUTH_CACHE_SIZE <= 0:
    BASIC_AUTH_CACHE_SIZE = 1000

AUTHORIZATION_CACHE_SIZE=env("AUTHORIZATION_CACHE_SIZE",default=2000)
if AUTHORIZATION_CACHE_SIZE <= 0:
    AUTHORIZATION_CACHE_SIZE = 2000


AUTH_BASIC_CACHE_EXPIRETIME=env('AUTH_BASIC_CACHE_EXPIRETIME',default=3600) #user access token life time in seconds
if AUTH_BASIC_CACHE_EXPIRETIME > 0:
    AUTH_BASIC_CACHE_EXPIRETIME = timedelta(seconds=AUTH_BASIC_CACHE_EXPIRETIME)
else:
    AUTH_BASIC_CACHE_EXPIRETIME = timedelta(seconds=3600)

#check whether the user token is valid per request
CHECK_AUTH_BASIC_PER_REQUEST=env("CHECK_AUTH_BASIC_PER_REQUEST",default=True)

AUTH_CACHE_EXPIRETIME=env('AUTH_CACHE_EXPIRETIME',default=3600) #user access token life time in seconds
if AUTH_CACHE_EXPIRETIME > 0:
    AUTH_CACHE_EXPIRETIME = timedelta(seconds=AUTH_CACHE_EXPIRETIME)
else:
    AUTH_CACHE_EXPIRETIME = timedelta(seconds=3600)

USER_ACCESS_TOKEN_LIFETIME=env('USER_ACCESS_TOKEN_LIFETIME',default=[0]) #user access token life time in days
USER_ACCESS_TOKEN_LIFETIME = [l if l > 0 else 0 for l in USER_ACCESS_TOKEN_LIFETIME]

USER_ACCESS_TOKEN_WARNING=env('USER_ACCESS_TOKEN_WARNING',default=7) #warning the user when the remaining lifetime is less than the configured days
if USER_ACCESS_TOKEN_WARNING > 0:
    USER_ACCESS_TOKEN_WARNING = timedelta(days=USER_ACCESS_TOKEN_WARNING)
else:
    USER_ACCESS_TOKEN_WARNING = None

AUTH_CACHE_CLEAN_HOURS=env('AUTH_CACHE_CLEAN_HOURS',default=[0]) #the hours in the day when auth cache can be cleared.

AUTHORIZATION_CACHE_CHECK_HOURS=env('AUTHORIZATION_CACHE_CHECK_HOURS',default=[0,12]) #the hours in the day when authorization cache can be checked.
AUTHORIZATION_CACHE_CHECK_INTERVAL=env('AUTHORIZATION_CACHE_CHECK_INTERVAL',default=0) #the interval to check authorization cache, if it is not greater than 0, use AUTHORIZATION_CACHE_CHECK_HOURS
if AUTHORIZATION_CACHE_CHECK_INTERVAL < 0:
    AUTHORIZATION_CACHE_CHECK_INTERVAL = 0

IDP_CACHE_CHECK_HOURS=env('IDP_CACHE_CHECK_HOURS',default=[0]) #the hours in the day when idp cach can be checked
IDP_CACHE_CHECK_INTERVAL=env('IDP_CACHE_CHECK_INTERVAL',default=0) #in seconds,the interval to check idp cache, if it is not greater than 0, use IDP_CACHE_CHECK_HOURS
if IDP_CACHE_CHECK_INTERVAL < 0:
    IDP_CACHE_CHECK_INTERVAL = 0

USERFLOW_CACHE_CHECK_HOURS=env('USERFLOW_CACHE_CHECK_HOURS',default=[0]) #the hours in the day when idp cach can be checked
USERFLOW_CACHE_CHECK_INTERVAL=env('USERFLOW_CACHE_CHECK_INTERVAL',default=0) #in seconds,the interval to check idp cache, if it is not greater than 0, use IDP_CACHE_CHECK_HOURS
if USERFLOW_CACHE_CHECK_INTERVAL < 0:
    USERFLOW_CACHE_CHECK_INTERVAL = 0

PREFERED_IDP_COOKIE_NAME=env('PREFERED_IDP_COOKIE_NAME',default='idp_auth2_dbca_wa_gov_au')
CACHE_KEY_PREFIX=env('CACHE_KEY_PREFIX',default="")

DBCA_STAFF_GROUPID=env('DBCA_STAFF_GROUPID',default="DBCA") # The emails belongs to group 'dbca staff' are allowed to self sign up (no pre-registration required).

AUTO_SIGNOUT_DELAY_SECONDS=env('AUTO_SIGNOUT_DELAY_SECONDS',default=10)


AUTH_CHECKING_THRESHOLD_TIME=env('AUTH_CHECKING_THRESHOLD_TIME',default=50) * 1000 #in milliseconds, should be less than 1000

SWITCH_TO_AUTH_LOCAL=env('SWITCH_TO_AUTH_LOCAL',default=False) #Switch to magic auth to login in user if azure ad b2c does not work.

PASSCODE_DAILY_LIMIT = env("PASSCODE_DAILY_LIMIT",100)
PASSCODE_TRY_TIMES = env("PASSCODE_TRY_TIMES",3)
PASSCODE_LENGTH=env('PASSCODE_LENGTH',default=6) 
PASSCODE_AGE=env('PASSCODE_AGE',default=300) #the age of verify code, in seconds
SIGNUP_TOKEN_LENGTH=env('SIGNUP_TOKEN_LENGTH',default=64) 
SIGNUP_TOKEN_AGE=env('SIGNUP_TOKEN_AGE',default=3600) #the age of signup token, in seconds

PASSCODE_DIGITAL=env('PASSCODE_DIGITAL',default=True)

# Logging settings - log to stdout/stderr
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'console': {'format': '%(asctime)s %(levelname)-8s %(name)-12s %(message)s'},
        'verbose': {'format': '%(asctime)s %(levelname)-8s %(message)s'},
    },
    'handlers': {
        'console': {
            'level': LOGLEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'console'
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'propagate': True,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'authome': {
            'handlers': ['console'],
            'level': LOGLEVEL,
        },
    }
}

if DEBUG:
    def show_toolbar(req):
        return req.path.startswith("/admin/") or req.path.startswith("/__debug__/") or req.path.startswith("/sso/loginstatus")

    INSTALLED_APPS.append('debug_toolbar')
    MIDDLEWARE.insert(0,'debug_toolbar.middleware.DebugToolbarMiddleware')
    DEBUG_TOOLBAR_CONFIG = {
        'SHOW_TOOLBAR_CALLBACK':show_toolbar
    }

def GET_CACHE_CONF(server,options={}):
    if server.lower().startswith('redis'):
        options["CLIENT_CLASS"] = "django_redis.client.DefaultClient"
        return {
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": server,
            "OPTIONS": options
        }
    else:
        return {
            'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
            'LOCATION': server,
            "OPTIONS": options
        }

ENABLE_B2C_JS_EXTENSION = env("ENABLE_B2C_JS_EXTENSION",default=True)
ADD_AUTH2_LOCAL_OPTION = env("ADD_AUTH2_LOCAL_OPTION",default=True)

SYNC_MODE = env("SYNC_MODE",True)
CACHE_SERVER = env("CACHE_SERVER")
CACHE_SERVER_OPTIONS = env("CACHE_SERVER_OPTIONS",default={})
CACHE_SESSION_SERVER = env("CACHE_SESSION_SERVER")
CACHE_SESSION_SERVER_OPTIONS = env("CACHE_SESSION_SERVER_OPTIONS",default={})
CACHE_USER_SERVER = env("CACHE_USER_SERVER")
CACHE_USER_SERVER_OPTIONS = env("CACHE_USER_SERVER_OPTIONS",default={})
USER_CACHE_ALIAS = None
GET_CACHE_KEY = lambda key:key
GET_USER_KEY = lambda userid:str(userid)
GET_USERTOKEN_KEY = lambda userid:"T{}".format(userid)
SESSION_CACHES = 0
USER_CACHES = 0
if CACHE_SERVER or CACHE_SESSION_SERVER or CACHE_USER_SERVER:
    CACHES = {}
    if CACHE_SERVER:
        CACHES['default'] = GET_CACHE_CONF(CACHE_SERVER,CACHE_SERVER_OPTIONS)
        if CACHE_KEY_PREFIX:
            default_key_pattern = "{}:{{}}".format(CACHE_KEY_PREFIX)
            GET_CACHE_KEY = lambda key:default_key_pattern.format(key)
        else:
            GET_CACHE_KEY = lambda key:key

    if CACHE_SESSION_SERVER:
        CACHE_SESSION_SERVER = [s.strip() for s in CACHE_SESSION_SERVER.split(",") if s and s.strip()]
        SESSION_CACHES = len(CACHE_SESSION_SERVER)
        if SESSION_CACHES == 1:
            CACHES["session"] = GET_CACHE_CONF(CACHE_SESSION_SERVER[0],CACHE_SESSION_SERVER_OPTIONS)
            SESSION_CACHE_ALIAS = "session"
        else:
            for i in range(0,SESSION_CACHES) :
                CACHES["session{}".format(i)] = GET_CACHE_CONF(CACHE_SESSION_SERVER[i],CACHE_USER_SERVER_OPTIONS)

            SESSION_CACHE_ALIAS = lambda sessionkey:"session{}".format((ord(sessionkey[-1]) + ord(sessionkey[-2])) % SESSION_CACHES)
        SESSION_ENGINE = "authome.cachesessionstoredebug" if DEBUG else  "authome.cachesessionstore"
    elif CACHE_SERVER:
        SESSION_ENGINE = "authome.cachesessionstoredebug" if DEBUG else  "authome.cachesessionstore"
        SESSION_CACHE_ALIAS = "default"
        SESSION_CACHES = 1

    if CACHE_USER_SERVER:
        CACHE_USER_SERVER = [s.strip() for s in CACHE_USER_SERVER.split(",") if s and s.strip()]
        USER_CACHES = len(CACHE_USER_SERVER)
        if USER_CACHES == 1:
            CACHES["user"] = GET_CACHE_CONF(CACHE_USER_SERVER[0])
            USER_CACHE_ALIAS = "user"
        else:
            for i in range(0,USER_CACHES) :
                CACHES["user{}".format(i)] = GET_CACHE_CONF(CACHE_USER_SERVER[i])

            USER_CACHE_ALIAS = lambda userid:"user{}".format(abs(userid) % USER_CACHES)
        if CACHE_KEY_PREFIX:
            user_key_pattern = "{}:{{}}".format(CACHE_KEY_PREFIX)
            usertoken_key_pattern = "{}:T{{}}".format(CACHE_KEY_PREFIX)
            GET_USER_KEY = lambda userid:user_key_pattern.format(userid)
            GET_USERTOKEN_KEY = lambda userid:usertoken_key_pattern.format(userid)
        else:
            GET_USER_KEY = lambda userid:str(userid)
            GET_USERTOKEN_KEY = lambda userid:"T{}".format(userid)
    elif CACHE_SERVER:
        if CACHE_KEY_PREFIX:
            user_key_pattern = "{}:user:{{}}".format(CACHE_KEY_PREFIX)
            usertoken_key_pattern = "{}:token:{{}}".format(CACHE_KEY_PREFIX)
        else:
            user_key_pattern = "user:{}"
            usertoken_key_pattern = "token:{}"
        GET_USER_KEY = lambda userid:user_key_pattern.format(userid)
        GET_USERTOKEN_KEY = lambda userid:usertoken_key_pattern.format(userid)
        USER_CACHE_ALIAS = "default"
        USER_CACHES = 1

    USER_CACHE_TIMEOUT = env("USER_CACHE_TIMEOUT",86400)
    if USER_CACHE_TIMEOUT <= 0:
        USER_CACHE_TIMEOUT = 86400

    STAFF_CACHE_TIMEOUT = env("STAFF_CACHE_TIMEOUT",86400 * 14)
    if STAFF_CACHE_TIMEOUT <= 0:
        STAFF_CACHE_TIMEOUT = None

