from django.core.cache import caches

_local_cache_timestamp = {
}

KEY_USER_GROUP_TREE = "UserGroupTree"
try:
    authorization_cache = caches["authorization"]
except:
    #authoriaztion cache not available
    print("Authorization cache is not available")
    authorization_cache = None

def is_local_cache_expired(key):
    cache_ts = _local_cache_timestamp.get(key)
    if not cache_ts:
        return True

    if not authorization_cache:
        if key == KEY_USER_GROUP_TREE:
            from .models import UserGroup
            data_ts = UserGroup.objects.all().order_by("-modified").first().modified.timestamp()
        else:
            data_ts = None
    else:
        data_ts = cache.get(key)
        if not data_ts:
            data_ts = None

    return cache_ts != data_ts

def set_local_cache_ts(key,ts=None):
    if not ts:
        ts = timezone.now().timestamp()
    else:
        ts = ts.timestamp()

    _local_cache_timestamp[key] = ts



        


