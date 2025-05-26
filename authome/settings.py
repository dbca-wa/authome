import os
import tomllib

from django.utils import timezone
from .utils import env, get_digest_function,is_cluster
from datetime import timedelta
import dj_database_url

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEBUG = env('DEBUG', False)
LOGLEVEL = env('LOGLEVEL',default='WARNING')
if LOGLEVEL not in ["DEBUG",'INFO','WARNING','ERROR','CRITICAL']:
    LOGLEVEL = 'DEBUG' if DEBUG else 'INFO'

TESTMODE = env("TESTMODE",default=False)

RELEASE = False if LOGLEVEL in ["DEBUG"] else True

SECURE_SSL_REDIRECT = env("SECURE_SSL_REDIRECT",default=False)
SECRET_KEY = env('SECRET_KEY', 'PlaceholderSecretKey')
PREVIOUS_SECRET_KEY=env("PREVIOUS_SECRET_KEY",default=None)
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

#enable auth2 cluster feature by setting AUTH2_CLUSTERID
AUTH2_CLUSTERID=env("AUTH2_CLUSTERID",default=None)
AUTH2_CLUSTER_ENDPOINT=env("AUTH2_CLUSTER_ENDPOINT",default=None)
DEFAULT_AUTH2_CLUSTER=env("DEFAULT_AUTH2_CLUSTER",default=False)
AUTH2_CLUSTERS_CHECK_INTERVAL=env("AUTH2_CLUSTERS_CHECK_INTERVAL",default=60)
if AUTH2_CLUSTERS_CHECK_INTERVAL <= 0:
    AUTH2_CLUSTERS_CHECK_INTERVAL = 60

AUTH2_CLUSTER_ENABLED = True if AUTH2_CLUSTERID and AUTH2_CLUSTER_ENDPOINT else False
if AUTH2_CLUSTER_ENABLED:
    if not SECRET_KEY:
        raise Exception("Must set SECRET_KEY for auth2 cluster feature")

EMAIL_HOST = env('EMAIL_HOST', default="")
EMAIL_PORT = env('EMAIL_PORT', 25)

AUTH2_DOMAIN = env("AUTH2_DOMAIN",default="auth2.dbca.wa.gov.au")
AUTH2_MONITORING_DIR=env("AUTH2_MONITORING_DIR")
AUTH2_MONITOR_EXPIREDAYS=env("AUTH2_MONITOR_EXPIREDAYS",default=10)


CAPTCHA_CHARS_IMAGE = env("CAPTCHA_CHARS_IMAGE",default="34689ABDEFGHJKLMNPQRTWXY")
CAPTCHA_CHARS_AUDIO = env("CAPTCHA_CHARS_AUDIO",default="0123456789")
CAPTCHA_DEFAULT_KIND = env("CAPTCHA_DEFAULT_KIND",default="image")
CAPTCHA_LEN = env("CAPTCHA_LEN",default=4)
if CAPTCHA_LEN < 4:
    CAPTCHA_LEN = 4

TOTP_SECRET_KEY_LENGTH = env("TOTP_SECRET_KEY_LENGTH",default=128)
TOTP_ISSUER = env("TOTP_ISSUER",default="DBCA")
TOTP_PREFIX = env("TOTP_PREFIX",default="DBCA")
TOTP_TIMESTEP = env("TOTP_TIMESTEP",default=30)
TOTP_VALIDWINDOW = env("TOTP_VALIDWINDOW",default=1)
TOTP_CHECK_LAST_CODE = env("TOTP_CHECK_LAST_CODE",default=True)
TOTP_DIGITS = env("TOTP_DIGITS",default=6)
TOTP_ALGORITHM = env("TOTP_ALGORITHM",default="SHA1")
TOTP_DIGEST = None

TOTP_ALGORITHM,TOTP_DIGEST = get_digest_function(TOTP_ALGORITHM)

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

_samesite_options = {"none":"None","lax":"Lax","strict":"Strict","null":None}
def _get_samesite(v):
    return _samesite_options.get(v.lower() if v else None,"Lax")

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SESSION_COOKIE_HTTPONLY = env('SESSION_COOKIE_HTTPONLY', True)
SESSION_COOKIE_SECURE = env('SESSION_COOKIE_SECURE', True)
CSRF_COOKIE_NAME = "csrftoken_auth2"
CSRF_COOKIE_SECURE = env('CSRF_COOKIE_SECURE', True)
CSRF_COOKIE_HTTPONLY = env('CSRF_COOKIE_HTTPONLY', True)
CSRF_TRUSTED_ORIGINS = env("CSRF_TRUSTED_ORIGINS",default=["https://{}".format("*.au" if h == '*' else ("*{}".format(h) if h.startswith('.') else h)) for h in ALLOWED_HOSTS])
CSRF_COOKIE_SAMESITE = env("CSRF_COOKIE_SAMESITE","Lax") or None
CSRF_COOKIE_SAMESITE = _get_samesite(CSRF_COOKIE_SAMESITE)

SESSION_COOKIE_SAMESITE = env("SESSION_COOKIE_SAMESITE","Lax") or None
SESSION_COOKIE_SAMESITE = _get_samesite(SESSION_COOKIE_SAMESITE)

GUEST_SESSION_AGE=env('GUEST_SESSION_AGE',default=3600) #login session timeout in seconds
SESSION_AGE=env('SESSION_AGE',default=1209600)
SESSION_COOKIE_AGE=SESSION_AGE + 86400

RAISE_EXCEPTION_4_INVALID_DOMAIN = env("RAISE_EXCEPTION_4_INVALID_DOMAIN",default=True)
DOMAIN_WHITELIST=env('DOMAIN_WHITELIST',default=[".dbca.wa.gov.au",".dpaw.wa.gov.au"])

if SESSION_COOKIE_DOMAIN:
    _session_cookie_domain_len = len(SESSION_COOKIE_DOMAIN)
    _session_cookie_domain_index = len(SESSION_COOKIE_DOMAIN) * -1
    _session_cookie_dot_index = len(SESSION_COOKIE_DOMAIN) * -1 - 1
else:
    _session_cookie_domain_len = 0
    _session_cookie_domain_index = 0
    _session_cookie_dot_index = 0

SESSION_COOKIE_DOMAINS=env("SESSION_COOKIE_DOMAINS",default=[])
i = 0
while i < len(SESSION_COOKIE_DOMAINS):
    #remove the leading "."
    if SESSION_COOKIE_DOMAINS[i][0] == ".":
        SESSION_COOKIE_DOMAINS[i] = SESSION_COOKIE_DOMAINS[i][1:]

    #check whether the domain is subdomain of other session domains
    if SESSION_COOKIE_DOMAINS[i].endswith(SESSION_COOKIE_DOMAIN):
        raise Exception("The domain({0}) is subdomain of domain({1})".format(SESSION_COOKIE_DOMAINS[i],SESSION_COOKIE_DOMAIN))
    elif SESSION_COOKIE_DOMAIN.endswith(SESSION_COOKIE_DOMAINS[i]):
        raise Exception("The domain({1}) is subdomain of domain({0})".format(SESSION_COOKIE_DOMAINS[i],SESSION_COOKIE_DOMAIN))

    if i > 0:
        j = 0
        while j < i:
            if SESSION_COOKIE_DOMAINS[i].endswith(SESSION_COOKIE_DOMAINS[j][0]):
                raise Exception("The domain({0}) is subdomain of domain({1})".format(SESSION_COOKIE_DOMAINS[i],SESSION_COOKIE_DOMAINS[j][0]))
            elif SESSION_COOKIE_DOMAINS[j][0].endswith(SESSION_COOKIE_DOMAINS[i]):
                raise Exception("The domain({1}) is subdomain of domain({0})".format(SESSION_COOKIE_DOMAINS[i],SESSION_COOKIE_DOMAINS[j][0]))
            j += 1

    SESSION_COOKIE_DOMAINS[i] = (SESSION_COOKIE_DOMAINS[i],len(SESSION_COOKIE_DOMAINS[i]),len(SESSION_COOKIE_DOMAINS[i]) * -1,len(SESSION_COOKIE_DOMAINS[i]) * -1 - 1)
    i += 1


def GET_SESSION_COOKIE_DOMAIN(domain):
    if domain[_session_cookie_domain_index:] == SESSION_COOKIE_DOMAIN and (len(domain) == _session_cookie_domain_len or domain[_session_cookie_dot_index] == "."):
        return  SESSION_COOKIE_DOMAIN
    else:
        for v in SESSION_COOKIE_DOMAINS:
            if domain[v[2]:] == v[0] and (len(domain) == v[1] or domain[v[3]] == "."):
                return v[0]

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
    'default': dj_database_url.config()
}

if "OPTIONS" in DATABASES['default']:
    DATABASES['default']["OPTIONS"]["options"] = "-c default_transaction_read_only=off"
else:
    DATABASES['default']["OPTIONS"] = {"options": "-c default_transaction_read_only=off"}

pool = DATABASES['default']["OPTIONS"].get("pool",False)
if isinstance(pool,str):
    DATABASES['default']["OPTIONS"]["pool"]=dict([d.strip().split("=",1) for d in pool.split(",") if d.strip()])
    for k in DATABASES['default']["OPTIONS"]["pool"].keys():
        v = DATABASES['default']["OPTIONS"]["pool"][k]
        try:
            DATABASES['default']["OPTIONS"]["pool"][k] = int(v)
        except ValueError as ex:
            try:
                DATABASES['default']["OPTIONS"]["pool"][k] = float(v)
            except ValueError as ex:
                if v.lower() == "true":
                    DATABASES['default']["OPTIONS"]["pool"][k] = True
                elif v.lower() == "false":
                    DATABASES['default']["OPTIONS"]["pool"][k] = False

    
if not DATABASES['default']["OPTIONS"].get("pool",False):
    DATABASES['default']["CONN_MAX_AGE"] = env("CONN_MAX_AGE",default=3600)
    DATABASES['default']["CONN_HEALTH_CHECKS"] = env("CONN_HEALTH_CHECKS",default=False)
    

# Static files configuration
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/sso/static/'
#STATICFILES_DIRS = (os.path.join(BASE_DIR, 'itassets', 'static'),)
STAFF_AUTH_CACHE_SIZE=env("STAFF_AUTH_CACHE_SIZE",default=2000)
if STAFF_AUTH_CACHE_SIZE <= 0:
    STAFF_AUTH_CACHE_SIZE = 2000

AUTH_CACHE_SIZE=env("AUTH_CACHE_SIZE",default=500)
if AUTH_CACHE_SIZE <= 0:
    AUTH_CACHE_SIZE = 500

EMAIL_GROUPS_CACHE_SIZE=env("EMAIL_GROUPS_CACHE_SIZE",default=2000)
if EMAIL_GROUPS_CACHE_SIZE <= 0:
    EMAIL_GROUPS_CACHE_SIZE = 2000

PUBLIC_EMAIL_GROUPS_CACHE_SIZE=env("PUBLIC_EMAIL_GROUPS_CACHE_SIZE",default=500)
if PUBLIC_EMAIL_GROUPS_CACHE_SIZE <= 0:
    PUBLIC_EMAIL_GROUPS_CACHE_SIZE = 500

BASIC_AUTH_CACHE_SIZE=env("BASIC_AUTH_CACHE_SIZE",default=1000)
if BASIC_AUTH_CACHE_SIZE <= 0:
    BASIC_AUTH_CACHE_SIZE = 1000

GROUPS_AUTHORIZATION_CACHE_SIZE=env("GROUPS_AUTHORIZATION_CACHE_SIZE",default=2000)
if GROUPS_AUTHORIZATION_CACHE_SIZE <= 0:
    GROUPS_AUTHORIZATION_CACHE_SIZE = 2000

AUTH_BASIC_CACHE_EXPIRETIME=env('AUTH_BASIC_CACHE_EXPIRETIME',default=3600) #user access token life time in seconds
if AUTH_BASIC_CACHE_EXPIRETIME > 0:
    AUTH_BASIC_CACHE_EXPIRETIME = timedelta(seconds=AUTH_BASIC_CACHE_EXPIRETIME)
else:
    AUTH_BASIC_CACHE_EXPIRETIME = timedelta(seconds=3600)

#check whether the user token is valid per request
CHECK_AUTH_BASIC_PER_REQUEST=env("CHECK_AUTH_BASIC_PER_REQUEST",default=True)

STAFF_AUTH_CACHE_EXPIRETIME=env('STAFF_AUTH_CACHE_EXPIRETIME',default=36000) #user access token life time in seconds
if STAFF_AUTH_CACHE_EXPIRETIME > 0:
    STAFF_AUTH_CACHE_EXPIRETIME = timedelta(seconds=STAFF_AUTH_CACHE_EXPIRETIME)
else:
    STAFF_AUTH_CACHE_EXPIRETIME = timedelta(seconds=36000)

AUTH_CACHE_EXPIRETIME=env('AUTH_CACHE_EXPIRETIME',default=3600) #user access token life time in seconds
if AUTH_CACHE_EXPIRETIME > 0:
    AUTH_CACHE_EXPIRETIME = timedelta(seconds=AUTH_CACHE_EXPIRETIME)
else:
    AUTH_CACHE_EXPIRETIME = timedelta(seconds=3600)

USER_ACCESS_TOKEN_LIFETIME=env('USER_ACCESS_TOKEN_LIFETIME',default=[0]) #user access token life time in days
USER_ACCESS_TOKEN_LIFETIME = [l if l > 0 else 0 for l in USER_ACCESS_TOKEN_LIFETIME]
USER_ACCESS_TOKEN_LIFETIME_SELFSERVICE=env('USER_ACCESS_TOKEN_LIFETIME_SELFSERVICE',default=[28]) #user access token life time in days
USER_ACCESS_TOKEN_LIFETIME_SELFSERVICE = [l if l > 0 else 0 for l in USER_ACCESS_TOKEN_LIFETIME_SELFSERVICE]

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

DBCA_STAFF_GROUPID=env('DBCA_STAFF_GROUPID',default="DBCA") # The emails belongs to group 'dbca staff' are allowed to self sign up (no pre-registration required).

AUTO_SIGNOUT_DELAY_SECONDS=env('AUTO_SIGNOUT_DELAY_SECONDS',default=10)


SWITCH_TO_AUTH_LOCAL=env('SWITCH_TO_AUTH_LOCAL',default=False) #Switch to magic auth to login in user if azure ad b2c does not work.

PASSCODE_DAILY_LIMIT = env("PASSCODE_DAILY_LIMIT",100)
PASSCODE_TRY_TIMES = env("PASSCODE_TRY_TIMES",3)
PASSCODE_LENGTH=env('PASSCODE_LENGTH',default=6)
PASSCODE_AGE=env('PASSCODE_AGE',default=300) #the age of verify code, in seconds
PASSCODE_RESEND_INTERVAL=env('PASSCODE_RESEND_INTERVAL',default=45) #the interval to resend passcode, in seconds
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

ENABLE_B2C_JS_EXTENSION = env("ENABLE_B2C_JS_EXTENSION",default=True)
ADD_AUTH2_LOCAL_OPTION = env("ADD_AUTH2_LOCAL_OPTION",default=True)

SYNC_MODE = env("SYNC_MODE",default="sync")

CACHE_KEY_PREFIX=env('CACHE_KEY_PREFIX',default="") or None
CACHE_KEY_VERSION_ENABLED = env('CACHE_KEY_VERSION_ENABLED',default=True)
if CACHE_KEY_PREFIX and CACHE_KEY_VERSION_ENABLED:
    #use the default key function
    key_pattern = "{}:{{}}:{{}}".format(CACHE_KEY_PREFIX)
    KEY_FUNCTION = lambda key,key_prefix,version : key_pattern.format(version,key)
elif CACHE_KEY_PREFIX:
    #has KEY_PREFIX, but KEY_VERSION_ENABLED is False
    key_pattern = "{}:{{}}".format(CACHE_KEY_PREFIX)
    KEY_FUNCTION = lambda key,key_prefix,version : key_pattern.format(key)
elif CACHE_KEY_VERSION_ENABLED:
    #KEY_PREFIX if None, but KEY_VERSION_ENABLED is True
    KEY_FUNCTION = lambda key,key_prefix,version : "{}:{}".format(version,key)
else:
    #KEY_PREFIX is None and KEY_VERSION_ENABLED is False
    KEY_FUNCTION = lambda key,key_prefix,version : key

PREVIOUS_CACHE_KEY_PREFIX=env('PREVIOUS_CACHE_KEY_PREFIX',default="") or None
PREVIOUS_CACHE_KEY_VERSION_ENABLED = env('PREVIOUS_CACHE_KEY_VERSION_ENABLED',default=True)
if PREVIOUS_CACHE_KEY_PREFIX and PREVIOUS_CACHE_KEY_VERSION_ENABLED:
    #use the default key function
    previous_key_pattern = "{}:{{}}:{{}}".format(PREVIOUS_CACHE_KEY_PREFIX)
    PREVIOUS_KEY_FUNCTION = lambda key,key_prefix,version : previous_key_pattern.format(version,key)
elif PREVIOUS_CACHE_KEY_PREFIX:
    #has KEY_PREFIX, but KEY_VERSION_ENABLED is False
    previous_key_pattern = "{}:{{}}".format(PREVIOUS_CACHE_KEY_PREFIX)
    PREVIOUS_KEY_FUNCTION = lambda key,key_prefix,version : previous_key_pattern.format(key)
elif PREVIOUS_CACHE_KEY_VERSION_ENABLED:
    #KEY_PREFIX if None, but KEY_VERSION_ENABLED is True
    PREVIOUS_KEY_FUNCTION = lambda key,key_prefix,version : "{}:{}".format(version,key)
else:
    #KEY_PREFIX is None and KEY_VERSION_ENABLED is False
    PREVIOUS_KEY_FUNCTION = lambda key,key_prefix,version : key

STANDALONE_CACHE_KEY_PREFIX=env("STANDALONE_CACHE_KEY_PREFIX") or None
STANDALONE_CACHE_KEY_VERSION_ENABLED = env('STANDALONE_CACHE_KEY_VERSION_ENABLED',default=True)
if STANDALONE_CACHE_KEY_PREFIX and STANDALONE_CACHE_KEY_VERSION_ENABLED:
    #use the default key function
    standalone_key_pattern = "{}:{{}}:{{}}".format(STANDALONE_CACHE_KEY_PREFIX)
    STANDALONE_KEY_FUNCTION = lambda key,key_prefix,version : standalone_key_pattern.format(version,key)
elif STANDALONE_CACHE_KEY_PREFIX:
    #has KEY_PREFIX, but KEY_VERSION_ENABLED is False
    standalone_key_pattern = "{}:{{}}".format(STANDALONE_CACHE_KEY_PREFIX)
    STANDALONE_KEY_FUNCTION = lambda key,key_prefix,version : standalone_key_pattern.format(key)
elif STANDALONE_CACHE_KEY_VERSION_ENABLED:
    #KEY_PREFIX if None, but KEY_VERSION_ENABLED is True
    STANDALONE_KEY_FUNCTION = lambda key,key_prefix,version : "{}:{}".format(version,key)
else:
    #KEY_PREFIX is None and KEY_VERSION_ENABLED is False
    STANDALONE_KEY_FUNCTION = lambda key,key_prefix,version : key

CACHE_SERVER = env("CACHE_SERVER")
CACHE_SERVER_OPTIONS = env("CACHE_SERVER_OPTIONS",default={})

CACHE_SESSION_SERVER = env("CACHE_SESSION_SERVER")
CACHE_SESSION_SERVER_OPTIONS = env("CACHE_SESSION_SERVER_OPTIONS",default={})

PREVIOUS_CACHE_SESSION_SERVER = env("PREVIOUS_CACHE_SESSION_SERVER")
PREVIOUS_CACHE_SESSION_SERVER_OPTIONS = env("PREVIOUS_CACHE_SESSION_SERVER_OPTIONS",default={})

CACHE_USER_SERVER = env("CACHE_USER_SERVER")
CACHE_USER_SERVER_OPTIONS = env("CACHE_USER_SERVER_OPTIONS",default={})

USER_CACHE_ALIAS = None
PREVIOUS_SESSION_CACHE_ALIAS=None

GET_DEFAULT_CACHE_KEY = lambda key:key
GET_USER_KEY = lambda userid:str(userid)
GET_USERTOKEN_KEY = lambda userid:"T{}".format(userid)

SESSION_CACHES = 0
PREVIOUS_SESSION_CACHES = 0
SESSION_CACHES = 0
USER_CACHES = 0

TRAFFIC_MONITOR_LEVEL = env('TRAFFIC_MONITOR_LEVEL',default=0) #0: disabled, 1:summary, 2: per domain
if not CACHE_SERVER or not CACHE_SERVER.lower().startswith('redis'):
    TRAFFIC_MONITOR_LEVEL = 0
if TRAFFIC_MONITOR_LEVEL > 0:
    try:
        REDIS_TRAFFIC_MONITOR_LEVEL = int(env('REDIS_TRAFFIC_MONITOR_LEVEL',default=0))
    except:
        REDIS_TRAFFIC_MONITOR_LEVEL = 0
    try:
        DB_TRAFFIC_MONITOR_LEVEL = int(env('DB_TRAFFIC_MONITOR_LEVEL',default=0))
    except:
        DB_TRAFFIC_MONITOR_LEVEL = 0
else:
    REDIS_TRAFFIC_MONITOR_LEVEL = 0
    DB_TRAFFIC_MONITOR_LEVEL = 0

TRAFFIC_MONITOR_INTERVAL=env('TRAFFIC_MONITOR_INTERVAL',default=3600)
if TRAFFIC_MONITOR_INTERVAL and TRAFFIC_MONITOR_INTERVAL > 0:
    if 86400 % TRAFFIC_MONITOR_INTERVAL > 0 :
        #One day can't be divided by interval, invalid, reset it to one hour
        TRAFFIC_MONITOR_INTERVAL = timedelta(seconds=3600)
    else:
        TRAFFIC_MONITOR_INTERVAL = timedelta(seconds=TRAFFIC_MONITOR_INTERVAL)
else:
    TRAFFIC_MONITOR_INTERVAL = timedelta(seconds=3600)

if REDIS_TRAFFIC_MONITOR_LEVEL > 0:
    import redis
    class MonitorEnabledConnection(redis.Connection):
        _cache = None
        def send_command(self, *args, **kwargs):
            try:
                starttime = timezone.localtime()
                status = "OK"
                return super().send_command(*args,**kwargs)
            except Exception as ex:
                status = ex.__class__.__name__
                raise
            finally:
                #cache and ignore the exceptions which are thrown before cache is fully initialized
                try:
                    MonitorEnabledConnection._cache.log_redisrequest("Redis",args[0],starttime,status)
                except:
                    try:
                        from . import cache
                        MonitorEnabledConnection._cache = cache.cache
                    except:
                        MonitorEnabledConnection._cache = None
                        
        def send_packed_command(self, command, check_health=True):
            try:
                starttime = timezone.localtime()
                status = "OK"
                return super().send_packed_command(command,check_health=check_health)
            except Exception as ex:
                status = ex.__class__.__name__
                raise
            finally:
                #cache and ignore the exceptions which are thrown before cache is fully initialized
                try:
                    MonitorEnabledConnection._cache.log_redisrequest("Redis","pipeline",starttime,status)
                except:
                    try:
                        from . import cache
                        MonitorEnabledConnection._cache = cache.cache
                    except:
                        MonitorEnabledConnection._cache = None
                
                
def GET_CACHE_CONF(cacheid,server,options={},key_function=KEY_FUNCTION):
    if server.lower().startswith('redis'):
        if "max_connections" not in options:
            options["max_connections"] = 10
        if REDIS_TRAFFIC_MONITOR_LEVEL > 0:
            options["connection_class"] = MonitorEnabledConnection
        if "cluster" in options:
            options = dict(options)
            cluster = options.pop("cluster")
        else:
            cluster = None
        if cluster is None:
            cluster = is_cluster(server)

        if cluster:
            if "require_full_coverage" not in options:
                options["require_full_coverage"] = False
            return {
                "BACKEND": "authome.redis.RedisClusterCache",
                "KEY_FUNCTION":key_function,
                "LOCATION": server,
                "CACHEID" : cacheid,
                "OPTIONS": options
            }
        else:
            return {
                "BACKEND": "authome.redis.RedisCache",
                "KEY_FUNCTION":key_function,
                "LOCATION": server,
                "CACHEID" : cacheid,
                "OPTIONS": options
            }
    else:
        return {
            'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
            "KEY_FUNCTION":key_function,
            'LOCATION': server,
            "OPTIONS": options
        }

if CACHE_SERVER or CACHE_SESSION_SERVER or CACHE_USER_SERVER:
    CACHES = {}
    if CACHE_SERVER:
        CACHES['default'] = GET_CACHE_CONF('default',CACHE_SERVER,CACHE_SERVER_OPTIONS,key_function=KEY_FUNCTION)
        if CACHE_KEY_PREFIX:
            default_key_pattern = "{}:{{}}".format(CACHE_KEY_PREFIX)
            GET_DEFAULT_CACHE_KEY = lambda key:default_key_pattern.format(key)
        else:
            GET_DEFAULT_CACHE_KEY = lambda key:key

    if CACHE_SESSION_SERVER:
        CACHE_SESSION_SERVER = [s.strip() for s in CACHE_SESSION_SERVER.split(",") if s and s.strip()]
        SESSION_CACHES = len(CACHE_SESSION_SERVER)
        if SESSION_CACHES == 1:
            CACHES["session"] = GET_CACHE_CONF("session",CACHE_SESSION_SERVER[0],CACHE_SESSION_SERVER_OPTIONS,key_function=KEY_FUNCTION)
            SESSION_CACHE_ALIAS = "session"
        else:
            for i in range(0,SESSION_CACHES) :
                name = "session{}".format(i)
                CACHES[name] = GET_CACHE_CONF(name,CACHE_SESSION_SERVER[i],env("CACHE_SESSION_SERVER{}_OPTIONS".format(i),default=CACHE_SESSION_SERVER_OPTIONS),key_function=KEY_FUNCTION)

            SESSION_CACHE_ALIAS = lambda sessionkey:"session{}".format((ord(sessionkey[-1]) + ord(sessionkey[-2])) % SESSION_CACHES)
        SESSION_ENGINE = "authome.sessionstore"
    elif CACHE_SERVER:
        SESSION_ENGINE = "authome.sessionstore"
        SESSION_CACHE_ALIAS = "default"
        SESSION_CACHES = 1

    if PREVIOUS_CACHE_SESSION_SERVER:
        PREVIOUS_CACHE_SESSION_SERVER = [s.strip() for s in PREVIOUS_CACHE_SESSION_SERVER.split(",") if s and s.strip()]
        PREVIOUS_SESSION_CACHES = len(PREVIOUS_CACHE_SESSION_SERVER)
        if PREVIOUS_SESSION_CACHES == 1:
            CACHES["previoussession"] = GET_CACHE_CONF("previoussession",PREVIOUS_CACHE_SESSION_SERVER[0],PREVIOUS_CACHE_SESSION_SERVER_OPTIONS,key_function=PREVIOUS_KEY_FUNCTION)
            PREVIOUS_SESSION_CACHE_ALIAS = "previoussession"
        else:
            for i in range(0,PREVIOUS_SESSION_CACHES) :
                name = "previoussession{}".format(i)
                CACHES[name] = GET_CACHE_CONF(name,PREVIOUS_CACHE_SESSION_SERVER[i],env("PREVIOUS_CACHE_SESSION_SERVER{}_OPTIONS".format(i),default=PREVIOUS_CACHE_SESSION_SERVER_OPTIONS),key_function=PREVIOUS_KEY_FUNCTION)

            PREVIOUS_SESSION_CACHE_ALIAS = lambda sessionkey:"previoussession{}".format((ord(sessionkey[-1]) + ord(sessionkey[-2])) % PREVIOUS_SESSION_CACHES)

    if CACHE_USER_SERVER:
        CACHE_USER_SERVER = [s.strip() for s in CACHE_USER_SERVER.split(",") if s and s.strip()]
        USER_CACHES = len(CACHE_USER_SERVER)
        if USER_CACHES == 1:
            CACHES["user"] = GET_CACHE_CONF("user",CACHE_USER_SERVER[0],CACHE_USER_SERVER_OPTIONS,key_function=KEY_FUNCTION)
            USER_CACHE_ALIAS = "user"
        else:
            for i in range(0,USER_CACHES) :
                name = "user{}".format(i)
                CACHES[name] = GET_CACHE_CONF(name,CACHE_USER_SERVER[i],env("CACHE_USER_SERVER{}_OPTIONS".format(i),CACHE_USER_SERVER_OPTIONS),key_function=KEY_FUNCTION)

            USER_CACHE_ALIAS = lambda userid:"user{}".format(abs(userid) % USER_CACHES)
        GET_USER_KEY = lambda userid:"user:{}".format(userid)
        GET_USERTOKEN_KEY = lambda userid:"token:{}".format(userid)
    elif CACHE_SERVER:
        GET_USER_KEY = lambda userid:"user:{}".format(userid)
        GET_USERTOKEN_KEY = lambda userid:"token:{}".format(userid)
        USER_CACHE_ALIAS = "default"
        USER_CACHES = 1

    USER_CACHE_TIMEOUT = env("USER_CACHE_TIMEOUT",86400)
    if USER_CACHE_TIMEOUT <= 0:
        USER_CACHE_TIMEOUT = 86400

    STAFF_CACHE_TIMEOUT = env("STAFF_CACHE_TIMEOUT",86400 * 14)
    if STAFF_CACHE_TIMEOUT <= 0:
        STAFF_CACHE_TIMEOUT = None


TEST_RUNNER=env("TEST_RUNNER","django.test.runner.DiscoverRunner")

START_OF_WEEK_MONDAY = env("START_OF_WEEK_MONDAY",default=True)

SESSION_COOKIE_DOMAIN_SEPARATOR=":"

AUTH2_INTERCONNECTION_TIMEOUT = env('AUTH2_INTERCONNECTION_TIMEOUT',default=5000)#timeout for interconnection among auth2 clusters, in milliseconds
AUTH2_INTERCONNECTION_TIMEOUT = round(AUTH2_INTERCONNECTION_TIMEOUT/1000,3)# convert AUTH2_INTERCONNECTION_TIMEOUT from milliseconds to seconds

AUTH_TOO_SLOW_THRESHOLD = env('AUTH_TOO_SLOW_THRESHOLD',default=5000)#timeout for user authentication, in milliseconds

SECRETKEY_EXPIREDAYS_WARNING=env('SECRETKEY_EXPIREDAYS_WARNING',default=14) #warning the user when the remaining lifetime is less than the configured days
if SECRETKEY_EXPIREDAYS_WARNING > 0:
    SECRETKEY_EXPIREDAYS_WARNING = timedelta(days=SECRETKEY_EXPIREDAYS_WARNING)
else:
    SECRETKEY_EXPIREDAYS_WARNING = timedelta(days=14)

SSL_VERIFY=env("SSL_VERIFY",default=True)

SOCIAL_AUTH_ADMIN_SEARCH_FIELDS=["uid"]

#TRAFFIC CONTROL SETTINGS
TRAFFICCONTROL_ENABLED = env('TRAFFICCONTROL_ENABLED',default=False)
TRAFFICCONTROL_MAX_BUCKETS=env('TRAFFICCONTROL_MAX_BUCKETS',default=25)
TRAFFICCONTROL_TIMEDIFF=env('TRAFFICCONTROL_TIMEDIFF',default=5)# milliseconds, the maximum time difference among auth2 server processes, it should be less than a few milliseconds
TRAFFICCONTROL_TIMEDIFF=timedelta(milliseconds=TRAFFICCONTROL_TIMEDIFF)
    
TRAFFICCONTROL_BOOKINGTIMEOUT=env('TRAFFICCONTROL_BOOKINGTIMEOUT',default=300)# seconds, the default timeout setting of  concurrency traffic control
if TRAFFICCONTROL_BOOKINGTIMEOUT <= 0:
    TRAFFICCONTROL_BOOKINGTIMEOUT = 300
elif TRAFFICCONTROL_BOOKINGTIMEOUT > 1800:
    TRAFFICCONTROL_BOOKINGTIMEOUT = 1800
    
if TRAFFICCONTROL_ENABLED:
    TRAFFICCONTROL_COOKIE_NAME = env('TRAFFICCONTROL_COOKIE_NAME')
    TRAFFICCONTROL_CACHE_CHECK_HOURS=env('TRAFFICCONTROL_CACHE_CHECK_HOURS',default=[0]) #the hours in the day when traffic control can be checked
    TRAFFICCONTROL_CACHE_CHECK_INTERVAL=env('TRAFFICCONTROL_CACHE_CHECK_INTERVAL',default=0) #in seconds,the interval to check traffic control cache, if it is not greater than 0, use TRAFFICCONTROL_CACHE_CHECK_HOURS
    if TRAFFICCONTROL_CACHE_CHECK_INTERVAL < 0:
        TRAFFICCONTROL_CACHE_CHECK_INTERVAL = 0
    
    TRAFFICCONTROL_CLUSTERID=env('TRAFFICCONTROL_CLUSTERID')
    TRAFFICCONTROL_TIMEOUT = env('TRAFFICCONTROL_TIMEOUT',default=100)
    if not TRAFFICCONTROL_TIMEOUT or TRAFFICCONTROL_TIMEOUT <= 0:
        TRAFFICCONTROL_TIMEOUT = 0.1
    else:
        TRAFFICCONTROL_TIMEOUT /= 1000

    TRAFFICCONTROL_CACHE_SERVER = env("TRAFFICCONTROL_CACHE_SERVER")
    TRAFFICCONTROL_CACHE_SERVER_OPTIONS = env("TRAFFICCONTROL_CACHE_SERVER_OPTIONS",default={})
    
    TRAFFICCONTROL_CACHE_ALIAS = None
    
    if CACHE_SERVER  or TRAFFICCONTROL_CACHE_SERVER:
        if AUTH2_CLUSTER_ENABLED:
            if TRAFFICCONTROL_CACHE_SERVER:
                TRAFFICCONTROL_CLUSTERID = AUTH2_CLUSTERID
                TRAFFICCONTROL_SUPPORTED = True
            elif TRAFFICCONTROL_CLUSTERID == AUTH2_CLUSTERID:
                #current auth2 cluster supports traffic control
                TRAFFICCONTROL_SUPPORTED = True
            else:
                #current auth2 cluster does not support traffic control, dependents on other cluster to implement traffic control
                TRAFFICCONTROL_SUPPORTED = False
                TRAFFICCONTROL_CACHE_SERVERS = 0
        else:
            #standalone auth2 server, should always support traffic control
            TRAFFICCONTROL_SUPPORTED = True
    
        if TRAFFICCONTROL_SUPPORTED :
            if TRAFFICCONTROL_CACHE_SERVER:
                TRAFFICCONTROL_CACHE_SERVER = [s.strip() for s in TRAFFICCONTROL_CACHE_SERVER.split(",") if s and s.strip()]
                TRAFFICCONTROL_CACHE_SERVERS = len(TRAFFICCONTROL_CACHE_SERVER)
                if TRAFFICCONTROL_CACHE_SERVERS == 1:
                    TRAFFICCONTROL_CACHE_ALIAS = "tcontrol"
                    CACHES[TRAFFICCONTROL_CACHE_ALIAS] = GET_CACHE_CONF(TRAFFICCONTROL_CACHE_ALIAS,TRAFFICCONTROL_CACHE_SERVER[0],TRAFFICCONTROL_CACHE_SERVER_OPTIONS,key_function=lambda key,key_prefix,version : key)
                else:
                    for i in range(0,TRAFFICCONTROL_CACHE_SERVERS) :
                        name = "tcontrol{}".format(i)
                        CACHES[name] = GET_CACHE_CONF(name,TRAFFICCONTROL_CACHE_SERVER[i],env("TRAFFICCONTROL_CACHE_SERVER{}_OPTIONS".format(i),default=TRAFFICCONTROL_CACHE_SERVER_OPTIONS),key_function=lambda key,key_prefix,version : key)
    
                    def TRAFFICCONTROL_CACHE_ALIAS(key):
                        h = hash(key) % TRAFFICCONTROL_CACHE_SERVERS
                        
                    TRAFFICCONTROL_CACHE_ALIAS = lambda key:"tcontrol{}".format(hash(key) % TRAFFICCONTROL_CACHE_SERVERS)
                GET_TRAFFICCONTROL_CACHE_KEY = lambda key:"T_{}".format(key)
            else:
                TRAFFICCONTROL_CACHE_ALIAS = "default"
                TRAFFICCONTROL_CACHE_SERVERS = 1
                if CACHE_KEY_PREFIX:
                    trafficcontrol_key_pattern = "{}:T_{{}}".format(CACHE_KEY_PREFIX)
                    GET_TRAFFICCONTROL_CACHE_KEY = lambda key:trafficcontrol_key_pattern.format(key)
                else:
                    GET_TRAFFICCONTROL_CACHE_KEY = lambda key:"T_{}".format(key)
    else:
        TRAFFICCONTROL_ENABLED = False
        TRAFFICCONTROL_SUPPORTED = False
else:
    TRAFFICCONTROL_SUPPORTED = False

# Sentry settings
project = tomllib.load(open(os.path.join(BASE_DIR, "pyproject.toml"), "rb"))
VERSION_NO = project["tool"]["poetry"]["version"]
SENTRY_DSN = env("SENTRY_DSN", None)
SENTRY_ENVIRONMENT = env("SENTRY_ENVIRONMENT", None)
SENTRY_SAMPLE_RATE = env("SENTRY_SAMPLE_RATE", 1.0)  # Error sampling rate
SENTRY_TRANSACTION_SAMPLE_RATE = env("SENTRY_TRANSACTION_SAMPLE_RATE", 0.0)  # Transaction sampling
SENTRY_PROFILES_SAMPLE_RATE = env("SENTRY_PROFILES_SAMPLE_RATE", 0.0)  # Proportion of sampled transactions to profile.
if SENTRY_DSN and SENTRY_ENVIRONMENT:
    import sentry_sdk

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        sample_rate=SENTRY_SAMPLE_RATE,
        traces_sample_rate=SENTRY_TRANSACTION_SAMPLE_RATE,
        profiles_sample_rate=SENTRY_PROFILES_SAMPLE_RATE,
        environment=SENTRY_ENVIRONMENT,
        release=VERSION_NO,
    )

