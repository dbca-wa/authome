from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in
from django.core import management
from django.utils import timezone
from django.db import models
from ipware.ip import get_client_ip
import hashlib

from django.contrib.sessions.models import Session

class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,)
    session = models.ForeignKey(Session, on_delete=models.CASCADE,)
    ip = models.GenericIPAddressField(null=True)

    @property
    def shared_id(self):
        return hashlib.sha256('{}{}{}'.format(
            timezone.now().month, self.user.email, settings.SECRET_KEY).lower().encode('utf-8')).hexdigest()


def user_logged_in_handler(sender, request, user, **kwargs):
    request.session.save()
    usersession, created = UserSession.objects.get_or_create(user=user, session_id=request.session.session_key)
    usersession.ip = get_client_ip(request)
    usersession.save()
    management.call_command("clearsessions", verbosity=0)

user_logged_in.connect(user_logged_in_handler)
