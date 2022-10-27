import ast
import hashlib
import io
import os
import urllib.parse
import re
import base64
import qrcode
import socket
import psutil
import logging
import traceback
import threading
from datetime import timedelta,datetime

from django.utils import timezone
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.db import connections
from django.core.cache import caches
from django.contrib import messages
from django_redis.cache import RedisCache

from django_redis import get_redis_connection

__version__ = '1.0.0'

logger = logging.getLogger(__name__)

LB_HASH_KEY_DIGEST_SIZE=8

_processid = None
def get_processid():
    global _processid
    if not _processid:
        _processid = "{}-{}-{}".format(socket.gethostname(),os.getpid(),get_process_starttime())
    return _processid

_process_starttime = None
def get_process_starttime():
    global _process_starttime
    if not _process_starttime:
        _process_starttime = timezone.make_aware(datetime.fromtimestamp(psutil.Process(os.getpid()).create_time())).strftime("%Y-%m-%dT%H:%M:%S.%f")
    return _process_starttime


def build_cookie_value(lb_hash_key,clusterid,signature,session_key,cookie_domain):
    from django.conf import settings
    if cookie_domain:
        if clusterid:
            return "{}|{}|{}|{}{}{}".format(lb_hash_key,clusterid,signature,session_key,settings.SESSION_COOKIE_DOMAIN_SEPATATOR,cookie_domain)
        else:
            return "{}{}{}".format(session_key,settings.SESSION_COOKIE_DOMAIN_SEPATATOR,cookie_domain)
    else:
        if clusterid:
            return "{}|{}|{}|{}".format(lb_hash_key,clusterid,signature,session_key)
        else:
            return session_key


_process_data = threading.local()
def attach_request(request):
    _process_data.request = request

def send_message(msg,level=messages.INFO):
    try:
        messages.add_message(_process_data.request, level, msg)
        return True
    except:
        return False
def get_useragent(request=None):
    try:
        if request:
            return request.META.get('HTTP_USER_AGENT')
        else:
            return _process_data.request.META.get('HTTP_USER_AGENT')
    except:
        return None

def get_source_session_cookie(request=None):
    from django.conf import settings
    if not request:
        request = _process_data.request
    if not request:
        return None
    return request.COOKIES.get(settings.SESSION_COOKIE_NAME)

def get_source_cookie_domain(request=None):
    cookie = get_source_session_cookie(request)
    return get_cookie_domain(cookie)

def get_cookie_domain(cookie):
    if not cookie:
        return None
    if settings.SESSION_COOKIE_DOMAIN_SEPATATOR in cookie:
        return cookie.rsplit(settings.SESSION_COOKIE_DOMAIN_SEPATATOR,1)[1]
    else:
        return None

def get_source_session_key(request=None):
    cookie = get_source_session_cookie(request)
    return get_session_key(cookie)

def get_session_key(cookie):
    from django.conf import settings
    if not cookie:
        return None
    return cookie.rsplit(settings.SESSION_COOKIE_DOMAIN_SEPATATOR,1)[0].rsplit("|",1)[-1]

def get_source_clusterid(request=None):
    cookie = get_source_session_cookie(request)
    return get_clusterid(cookie)

def get_clusterid(cookie):
    if not cookie:
        return None
    cookie_components = cookie.split("|",3)
    if len(cookie_components) < 4:
        return None
    else:
        return cookie_components[1]

def get_source_lb_hash_key(request=None):
    cookie = get_source_session_cookie(request)
    return get_lb_hash_key(cookie)

def get_lb_hash_key(cookie):
    if not cookie:
        return None
    cookie_components = cookie.split("|",3)
    if len(cookie_components) < 4:
        return None
    else:
        return cookie_components[0]

def get_request_path(request=None):
    try:
        if request:
            path = request.headers.get("x-upstream-request-uri")
        else:
            path = _process_data.request.headers.get("x-upstream-request-uri")
        if not path:
            #can't get the original path, use request path directly
            path = _process_data.request.get_full_path()

        return "{}{}".format(get_host( _process_data.request), path)
    except:
        return None

def get_request_pathinfo(request=None):
    try:
        if request:
            path = request.headers.get("x-upstream-request-uri")
        else:
            path = _process_data.request.headers.get("x-upstream-request-uri")
        if path:
            #get the original request path
            #remove the query string
            try:
                path = path[:path.index("?")]
            except:
                pass
        else:
            #can't get the original path, use request path directly
            path = _process_data.request.path_info

        return "{}{}".format(get_host( _process_data.request), path)
    except:
        return None


def _convert(key,value, default=None, required=False, value_type=None,subvalue_type=None):
    """
    Convert the env variable to required data type
    """
    if value_type is None:
        #value type is not specified, use default value's type
        if default is not None:
            value_type = default.__class__
    if subvalue_type is None:
        #sub value type is not specified, if default value is list type, use the first member's type
        if default and isinstance(default,(list,tuple)):
            subvalue_type = default[0].__class__

    if value_type is None:
        #Can't find the value type, return value directly
        return value
    elif isinstance(value, value_type):
        #if value's type is the same as required type, return value directly
        return value
    elif issubclass(value_type, list):
        #required value type is list
        if isinstance(value, tuple):
            #value's type is tuple, create a list and return
            return list(value)
        else:
            #treat value as a comma separated string, get rid of the heading and tail space
            value = str(value).strip()
            if not value:
                return []
            else:
                result = []
                for subvalue in value.split(","):
                    subvalue = subvalue.strip()
                    if not subvalue:
                        continue
                    try:
                        subvalue = ast.literal_eval(subvalue)
                    except (SyntaxError, ValueError):
                        pass
                    result.append(_convert(key,subvalue,required=True,value_type=subvalue_type))
                return result
    elif issubclass(value_type, tuple):
        if isinstance(value, list):
            return tuple(value)
        else:
            value = str(value).strip()
            if not value:
                return tuple()
            else:
                result = []
                for subvalue in value.split(","):
                    subvalue = subvalue.strip()
                    if not subvalue:
                        continue
                    try:
                        subvalue = ast.literal_eval(subvalue)
                    except (SyntaxError, ValueError):
                        pass
                    result.append(_convert(key,subvalue,required=True,value_type=subvalue_type))
                return tuple(result)
    elif issubclass(value_type,dict):
        #required value type is dict, treat value is a comma separated key=value string.
        result = dict([ ( d.strip()  for d in item.split("=",1))  for item in value.split(",") if item and item.strip() ])
        for k,v in result.items():
            if default and default.get(k) is not None:
                result[k] = _convert(k,v,default=default.get(k))
            else:
                try:
                    result[k] = ast.literal_eval(v)
                except:
                   pass
        return result
    elif issubclass(value_type, bool):
        value = str(value).strip()
        if not value:
            return False
        elif value.lower() == 'true':
            return True
        elif value.lower() == 'false':
            return False
        else:
            raise Exception("'{}' is a boolean environment variable, only accept value 'true' ,'false' and '' with case insensitive, but the configured value is '{}'".format(key, value))
    elif issubclass(value_type, int):
        return int(value)
    elif issubclass(value_type, float):
        return float(value)
    else:
        raise Exception("'{0}' is a {1} environment variable, but {1} is not supported now".format(key, value_type))


def env(key, default=None, required=False, value_type=None,subvalue_type=None):
    """
    Retrieves environment variables and returns Python natives. The (optional)
    default will be returned if the environment variable does not exist.
    """
    try:
        value = os.environ[key]
        if value:
            value = value.strip()
        value = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        pass
    except KeyError:
        if default is not None or not required:
            return default
        raise Exception("Missing required environment variable '%s'" % key)

    return _convert(key,value,default=default,required=required,value_type=value_type,subvalue_type=subvalue_type)


url_re = re.compile("^((https?://)?(?P<domain>[^:/\?]+)?(:(?P<port>[0-9]+))?)?(?P<path>/[^\?]*)?(\?(?P<parameters>.*))?$",re.IGNORECASE)
def parse_url(url):
    """
    Return domain from url
    """
    if url:
        m = url_re.search(url)
        if m :
            return {
                "url":url,
                "domain":m.group("domain"),
                "port":m.group("port"),
                "path":m.group("path"),
                "parameters":m.group("parameters")
            }
        else:
            raise Exception("Invalid url({})".format(url))
    else:
        raise Exception("Url is empty")

domain_url_re = re.compile("^(https?://)?(?P<domain>[^:/\?]+)",re.IGNORECASE)
def get_domain(url):
    """
    Return domain from url
    """
    if url:
        m = domain_url_re.search(url)
        if m :
            return m.group('domain')
        else:
            return None
    else:
        return None

def get_totpurl(secret, name, issuer, timestep, prefix=None,algorithm="SHA1",digits=6):
    """
    Return totp url
    """
    prefix = prefix or issuer

    prefix = urllib.parse.quote(prefix)
    issuer = urllib.parse.quote(issuer)

    return "otpauth://totp/{0}:{1}?secret={2}&period={3}&algorithm={5}&issuer={4}&digits={6}".format(prefix , name, secret, timestep, issuer,algorithm,digits)

def encode_qrcode(totpurl):
    """
    Build a qrcode for totpurl and encoded it as base64 string
    """
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
    )
    logger.debug("totpurl = {}".format(totpurl))
    qr.add_data(totpurl)
    qr.make()
    img = qr.make_image()
    buff = io.BytesIO()
    img.save(buff, format="PNG")
    return "data:image/png;base64,"+base64.b64encode(buff.getvalue()).decode("utf-8")

digest_map = {}
def get_digest_function(algorithm):
    """
    params:
      algorithm: digest algorithm,case insensitive,
    return (algorithm name(returned from digest function), related digest function) via digest algorithm 

    """
    algorithm = algorithm.upper()
    result = digest_map.get(algorithm)
    if result:
        return result

    for k,v in hashlib.__dict__.items():
        if not callable(v):
            continue
        try:
            if v().name.upper() == algorithm:
                result = (v().name.upper(),v)
                digest_map[algorithm] = result
                return result
        except:
            continue

    raise Exception("Digest algorithm({}) Not Support".format(algorithm))

def format_datetime(dt):
    return timezone.localtime(dt).strftime("%Y-%m-%d %H:%M:%S") if dt else None

def parse_datetime(dt):
    return timezone.make_aware(datetime.strptime(dt,"%Y-%m-%d %H:%M:%S")) if dt else None

def encode_datetime(dt):
    return timezone.localtime(dt).strftime("%Y-%m-%dT%H:%M:%S") if dt else None

def decode_datetime(dt):
    return timezone.make_aware(datetime.strptime(dt,"%Y-%m-%dT%H:%M:%S")) if dt else None

def encode_timedelta(df):
    return (df.days * 86400 + df.seconds) if df else None

def decode_timedelta(df):
    return timedetla(seconds=df) if df else None


def format_timedelta(td,unit="s"):
    days = 0
    hours = 0
    minutes = 0
    seconds = 0
    if isinstance(td,timedelta):
        days = td.days
        seconds = td.seconds
        hours = int(seconds / (60 * 60))
        seconds = seconds % (60 * 60)
        minutes = int(seconds / 60)
        seconds = seconds % 60
    else:
        if unit == "d":
            days = td
        elif unit == "h":
            days = int(td / 24)
            hours = td % 24
        elif unit == "m":
            days = int(td / (24 * 60))
            minutes = td % (24 * 60)
            hours = int(minutes / 60)
            minutes = minutes % 60
        elif unit == "s":
            days = int(td / (24 * 60 * 60))
            seconds = td % (24 * 60 * 60)
            hours = int(seconds / (60 * 60))
            seconds = seconds % (60 * 60)
            minutes = int(seconds / 60)
            seconds = seconds % 60


    days = "" if days == 0 else ("{} day".format(days) if days == 1 else "{} days".format(days))
    hours = "" if hours == 0 else ("{} hour".format(hours) if hours == 1 else "{} hours".format(hours))
    minutes = "" if minutes == 0 else ("{} minute".format(minutes) if minutes == 1 else "{} minutes".format(minutes))
    seconds = "" if seconds == 0 else ("{} second".format(seconds) if seconds == 1 else "{} seconds".format(seconds))

    return " ".join(d for d in [days,hours,minutes,seconds] if d)


def _get_host(request):
    """
    Get non-null remote host from request
    """
    global get_host
    if request.headers.get("x-upstream-request-uri"):
        if request.headers.get("x-upstream-server-name"):
            #header 'x-upstream-server-name' is used, get the remote host from header 'x-upstream-server-name' first, if not found, get it from request host
            get_host = _get_host1
        else:
            #header 'x-upstream-server-name' is not used, get the remote host from request host directly
            get_host = _get_host2
        return get_host(request)
    else:
        return request.get_host()

def _get_host1(request):
    """
    get the remote host from header 'x-upstream-server-name' first, if not found, get it from request host
    """
    return request.headers.get("x-upstream-server-name") or request.get_host()

def _get_host2(request):
    """
    get the remote host from request host directly
    """
    return request.get_host()

get_host = _get_host

def sign_session_cookie(hash_key,clusterid,session_key,secretkey):
    h = hashlib.blake2b(digest_size=LB_HASH_KEY_DIGEST_SIZE)
    h.update("{}{}{}{}".format(hash_key,clusterid,session_key,secretkey).encode())
    return h.hexdigest()

def add_to_list(l,o):
    """
    Add a object or list or tuple to list object, if list object is None, create a new list
    return the list object
    """
    if l is None:
        if isinstance(o,list):
            return o
        else:
            return [o]
    elif isinstance(o,list):
        for m in o:
            l.append(m)
        return l
    else:
        l.append(o)
        return l

def add_to_map(m,k,v):
    """
    Add object to map object, if map object is None, create a new map
    return the list object
    """
    if m is None:
        return {k:v}
    else:
        m[k] = v
        return m

def ping_database(dbalias):
    msg = "OK"
    healthy = True
    with connections[dbalias].cursor() as cursor:
        try:
            cursor.execute("select 1")
            v = cursor.fetchone()[0]
            if v != 1:
                healthy = False
                msg = "Not Available"
        except Exception as ex:
            healthy = False
            msg = str(ex)
    return (healthy,msg)

redis_re = re.compile("^\s*(?P<protocol>[a-zA-Z]+)://((?P<user>[^:@]+)?(:(?P<password>[^@]+))?@)?(?P<server>\S+)\s*$")
def print_redisserver(server):
    """
    Return a printable redis server url
    """
    if isinstance(server,RedisCache):
        server = server._server
    elif not isinstance(server,str):
        return str(server)

    try:
        m = redis_re.search(server)
        return "{0}://xxx:xxx@{1}".format(m.group("protocol"),m.group("server"))
    except:
        return "xxxxxx"

    
def ping_redisserver(serveralias):
    try:
        with get_redis_connection(serveralias) as conn:
            data = conn.info("server")
            serverinfo = {}
            if data.get("uptime_in_seconds"):
                serverinfo["starttime"] = timezone.localtime() - timedelta(seconds=data.get("uptime_in_seconds"))
            else:
                serverinfo["starttime"] = "N/A"

            return (True, "OK" ,serverinfo)
    except Exception as ex:
        return (False,str(ex),{})


def ping_cacheserver(serveralias):
    try:
        caches[serveralias].set("PING","PONG")
        return (True, "OK")
    except Exception as ex:
        return (False,str(ex))


def print_cookies(request):
    msg = "All request cookies"
    for k,v in request.COOKIES.items():
        msg = "{}\n\t{} = {}".format(msg,k,v)

    logger.debug(msg)

def print_headers(request,headers=None):
    msg = "Request headers"
    if headers:
        for k in headers:
            k = k.upper()
            msg = "{}\n\t{} = {}".format(msg,k,request.headers.get(k) or "")
    else:
        for k,v in request.headers.items():
            msg = "{}\n\t{} = {}".format(msg,k,v)
    logger.debug(msg)

def print_request_meta(request):
    msg = "Request meta data"
    for k,v in request.META.items():
        msg = "{}\n\t{} = {}".format(msg,k,v)
    logger.debug(msg)


def create_secret_key(length=64):
    from django.utils.crypto import  get_random_string
    import string
    return get_random_string(length, string.digits + string.ascii_letters + "`~!@$%^&*()_+-={}|[]:;,./<>?")


