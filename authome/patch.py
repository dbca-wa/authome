import logging

from django.contrib import auth
from django.utils import timezone

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from .models import User
from .cache import get_usercache

from . import performance

logger = logging.getLogger(__name__)

anonymoususer = auth.models.AnonymousUser()

"""
override django builtin method _get_user
To improve the perforance and debug, provide different function in each scenario, (the combination of debug and usercache)

"""
if settings.USER_CACHE_ALIAS:
    def _get_user(request):
        """
        Return the user model instance associated with the given request session.
        If no user is retrieved, return an instance of `AnonymousUser`.
        """
        user = None
        try:
            userid = auth._get_user_session_key(request)
            userkey = settings.GET_USER_KEY(userid)
            usercache = get_usercache(userid)
            
            performance.start_processingstep("get_user_from_cache")
            try:
                user = usercache.get(userkey)
            finally:
                performance.end_processingstep("get_user_from_cache")
                pass

            if not user:
                performance.start_processingstep("fetch_user_from_db")
                try:
                    user = User.objects.get(pk = userid)
                finally:
                    performance.end_processingstep("fetch_user_from_db")
                    pass

                performance.start_processingstep("set_user_to_cache")
                try:
                    usercache.set(userkey,user,settings.USER_CACHE_TIMEOUT)
                finally:
                    performance.end_processingstep("set_user_to_cache")
                    pass

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
        user = None
        try:
            userid = auth._get_user_session_key(request)
            performance.start_processingstep("fetch_user_from_db")
            try:
                user = User.objects.get(pk = userid)
            finally:
                performance.end_processingstep("fetch_user_from_db")
                pass
        except KeyError:
            pass
        except ObjectDoesNotExist as ex:
            pass

        return user or anonymoususer

auth.get_user = _get_user


