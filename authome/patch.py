import logging

from django.contrib import auth
from django.utils import timezone

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from .models import User
from .utils import get_usercache

logger = logging.getLogger(__name__)

usercache = get_usercache()

anonymoususer = auth.models.AnonymousUser()

if usercache:
    if settings.RELEASE:
        def _get_user(request):
            """
            Return the user model instance associated with the given request session.
            If no user is retrieved, return an instance of `AnonymousUser`.
            """
            user = None
            try:
                userid = auth._get_user_session_key(request)
                userkey = settings.GET_USER_KEY(userid)
                user = usercache.get(userkey)
                if not user:
                    user = User.objects.get(pk = userid)
                    usercache.set(userkey,user,settings.USER_CACHE_TIMEOUT)
            except KeyError:
                pass
            except ObjectDoesNotExist as ex:
                pass
    
            return user or anonymoususer
    else:
        def _get_user(request):
            """
            Return the user model instance associated with the given request session.
            If no user is retrieved, return an instance of `AnonymousUser`.
            """
            logger.debug("Start to retrieve the user data from usercache")
            now = timezone.now()
            user = None
            try:
                userid = auth._get_user_session_key(request)
                userkey = settings.GET_USER_KEY(userid)
                user = usercache.get(userkey)
                if not user:
                    user = User.objects.get(pk = userid)
                    usercache.set(userkey,user,settings.USER_CACHE_TIMEOUT)
                    diff = timezone.now() - now
                    logger.debug("Spend {} milliseconds to cache the user({}) data from database to usercache".format(round((diff.seconds * 1000 + diff.microseconds)/1000),user.email))
                else:
                    diff = timezone.now() - now
                    logger.debug("Spend {} milliseconds to get the user({}) data from usercache".format(round((diff.seconds * 1000 + diff.microseconds)/1000),user.email))
            except KeyError:
                pass
            except ObjectDoesNotExist as ex:
                pass
    
            return user or anonymoususer

else:

    if settings.RELEASE:
        def _get_user(request):
            """
            Return the user model instance associated with the given request session.
            If no user is retrieved, return an instance of `AnonymousUser`.
            """
            user = None
            try:
                userid = auth._get_user_session_key(request)
                user = User.objects.get(pk = userid)
            except KeyError:
                pass
            except ObjectDoesNotExist as ex:
                pass
    
            return user or anonymoususer
    else:
        def _get_user(request):
            """
            Return the user model instance associated with the given request session.
            If no user is retrieved, return an instance of `AnonymousUser`.
            """
            logger.debug("Start to retrieve the user data from database")
            now = timezone.now()
            user = None
            try:
                userid = auth._get_user_session_key(request)
                user = User.objects.get(pk = userid)
            except KeyError:
                pass
            except ObjectDoesNotExist as ex:
                pass
            finally:
                diff = timezone.now() - now
                logger.debug("Spend {} milliseconds to retrieve  the user({}) data from  database".format(round((diff.seconds * 1000 + diff.microseconds)/1000),user.email if user else "AnonymousUser"))
    
            return user or anonymoususer


auth.get_user = _get_user


