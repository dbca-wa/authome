import os
from confy import env, database, cache

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Define the following in the environment:
SECRET_KEY = env('SECRET_KEY')
DEBUG = env('DEBUG', False)
ALLOWED_HOSTS = [env('ALLOWED_DOMAIN'), ]
INTERNAL_IPS = ['127.0.0.1', '::1']


# Application definition

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'social.apps.django_app.default',
    'authome'
]

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'social.backends.azuread.AzureADOAuth2',
)

# Azure AD settings
AZUREAD_AUTHORITY = env('AZUREAD_AUTHORITY', 'https://login.microsoftonline.com')
AZUREAD_RESOURCE = env('AZUREAD_RESOURCE', '00000002-0000-0000-c000-000000000000')
SOCIAL_AUTH_AZUREAD_OAUTH2_KEY = env('AZUREAD_CLIENTID', 'clientid')
SOCIAL_AUTH_AZUREAD_OAUTH2_SECRET = env('AZUREAD_SECRETKEY', 'secret')
SOCIAL_AUTH_REDIRECT_IS_HTTPS = True
SOCIAL_AUTH_TRAILING_SLASH = False
SOCIAL_AUTH_LOGIN_REDIRECT_URL = "/"
SOCIAL_AUTH_PIPELINE = (
    'social.pipeline.social_auth.social_details',
    'social.pipeline.social_auth.social_uid',
    'social.pipeline.social_auth.auth_allowed',
    'social.pipeline.social_auth.social_user',
    'social.pipeline.user.get_username',
    'social.pipeline.social_auth.associate_by_email',
    'social.pipeline.user.create_user',
    'social.pipeline.social_auth.associate_user',
    'social.pipeline.social_auth.load_extra_data',
    'social.pipeline.user.user_details',
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
CACHES = {'default': cache.config()}

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
USE_I18N = True
USE_L10N = True
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


DATABASES = {'default': database.config()}
ROOT_URLCONF = 'authome.urls'
WSGI_APPLICATION = 'authome.wsgi.application'

