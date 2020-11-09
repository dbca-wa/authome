import os
from authome.utils import env
from datetime import timedelta
import dj_database_url

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEBUG = env('DEBUG', False)
SECRET_KEY = env('SECRET_KEY', 'PlaceholderSecretKey')
if not DEBUG:
    ALLOWED_HOSTS = env('ALLOWED_DOMAINS', '').split(',')
else:
    ALLOWED_HOSTS = ['*']
INTERNAL_IPS = ['127.0.0.1', '::1']
ROOT_URLCONF = 'authome.urls'
WSGI_APPLICATION = 'authome.wsgi.application'


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
    'social_core.backends.azuread.AzureADOAuth2',
)

# Azure AD settings
AZUREAD_AUTHORITY = env('AZUREAD_AUTHORITY', 'https://login.microsoftonline.com')
AZUREAD_RESOURCE = env('AZUREAD_RESOURCE', '00000002-0000-0000-c000-000000000000')
SOCIAL_AUTH_AZUREAD_OAUTH2_KEY = env('AZUREAD_CLIENTID', 'clientid')
SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET = env('AZUREAD_SECRETKEY', 'secret')
SOCIAL_AUTH_REDIRECT_IS_HTTPS = True
SOCIAL_AUTH_TRAILING_SLASH = False
SOCIAL_AUTH_LOGIN_REDIRECT_URL = "/"
SOCIAL_AUTH_INACTIVE_USER_URL = "/ssouser/inactive-user"
SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.social_auth.associate_by_email',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
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

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
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
        'DIRS': [],
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

# Static files configuration
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATIC_URL = '/static/'
#STATICFILES_DIRS = (os.path.join(BASE_DIR, 'itassets', 'static'),)
AUTH_CACHE_SIZE=env("AUTH_CACHE_SIZE",default=2000)
if AUTH_CACHE_SIZE <= 0:
    AUTH_CACHE_SIZE = 2000

AUTH_TOKEN_CACHE_SIZE=env("AUTH_TOKEN_CACHE_SIZE",default=1000)
if AUTH_TOKEN_CACHE_SIZE <= 0:
    AUTH_TOKEN_CACHE_SIZE = 1000

AUTHORIZATION_CACHE_SIZE=env("AUTHORIZATION_CACHE_SIZE",default=2000)
if AUTHORIZATION_CACHE_SIZE <= 0:
    AUTHORIZATION_CACHE_SIZE = 2000


AUTH_TOKEN_CACHE_EXPIRETIME=env('AUTH_TOKEN_CACHE_EXPIRETIME',default=3600) #user access token life time in seconds
if AUTH_TOKEN_CACHE_EXPIRETIME > 0:
    AUTH_TOKEN_CACHE_EXPIRETIME = timedelta(seconds=AUTH_TOKEN_CACHE_EXPIRETIME)
else:
    AUTH_TOKEN_CACHE_EXPIRETIME = timedelta(seconds=3600)

CHECK_AUTH_TOKEN_PER_REQUEST=env("CHECK_AUTH_TOKEN_PER_REQUEST",default=False)

AUTH_CACHE_EXPIRETIME=env('AUTH_CACHE_EXPIRETIME',default=3600) #user access token life time in seconds
if AUTH_CACHE_EXPIRETIME > 0:
    AUTH_CACHE_EXPIRETIME = timedelta(seconds=AUTH_CACHE_EXPIRETIME)
else:
    AUTH_CACHE_EXPIRETIME = timedelta(seconds=3600)

USER_ACCESS_TOKEN_LIFETIME=env('USER_ACCESS_TOKEN_LIFETIME',default=28) #user access token life time in days
if USER_ACCESS_TOKEN_LIFETIME > 0:
    USER_ACCESS_TOKEN_LIFETIME = timedelta(days=USER_ACCESS_TOKEN_LIFETIME)
else:
    USER_ACCESS_TOKEN_LIFETIME = None

USER_ACCESS_TOKEN_WARNING=env('USER_ACCESS_TOKEN_WARNING',default=7) #warning the user when the remaining lifetime is less than the configured days
if USER_ACCESS_TOKEN_WARNING > 0:
    USER_ACCESS_TOKEN_WARNING = timedelta(days=USER_ACCESS_TOKEN_WARNING)
else:
    USER_ACCESS_TOKEN_WARNING = None

AUTH_CACHE_CLEAN_HOURS=env('AUTH_CACHE_CLEAN_HOURS',default=[0]) #the hours in the day when auth cache can be cleared.

AUTHORIZATION_CACHE_CHECK_HOURS=env('AUTHORIZATION_CACHE_CHECK_HOURS',default=[0,12]) #the hours in the day when authorization cache can be checked.

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
            'level': 'DEBUG' if DEBUG else 'INFO',
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
            'level': 'DEBUG' if DEBUG else 'INFO'
        },
    }
}

