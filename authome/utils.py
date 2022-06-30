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
from datetime import timedelta,datetime

from django.utils import timezone
from django.contrib.auth import REDIRECT_FIELD_NAME

__version__ = '1.0.0'

logger = logging.getLogger(__name__)

LB_HASH_KEY_DIGEST_SIZE=8

_processid = None
def get_processid():
    global _processid
    if not _processid:
        processcreatetime = timezone.make_aware(datetime.fromtimestamp(psutil.Process(os.getpid()).create_time())).strftime("%Y-%m-%d %H:%M:%S.%f")
        _processid = "{}-{}-{}".format(socket.gethostname(),processcreatetime,os.getpid())
    return _processid

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

def sign_lb_hash_key(hash_key,clusterid,secretkey):
    h = hashlib.blake2b(digest_size=LB_HASH_KEY_DIGEST_SIZE)
    h.update("{}{}{}".format(hash_key,clusterid,secretkey).encode())
    return h.hexdigest()

def add_to_list(l,o):
    """
    Add object to list object, if list object is None, create a new list
    return the list object
    """
    if l is None:
        return [o]
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
