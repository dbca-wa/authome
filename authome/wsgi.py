"""
WSGI config for authome project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/howto/deployment/wsgi/
"""

import os
import confy
from django.core.wsgi import get_wsgi_application

confy.read_environment_file(".env")

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "authome.settings")

application = get_wsgi_application()
