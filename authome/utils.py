import ast
import io
import os
import urllib.parse
import re
import base64
import qrcode

from django.contrib.auth import REDIRECT_FIELD_NAME

__version__ = '1.0.0'


def _convert(key,value, default=None, required=False, value_type=None,subvalue_type=None):
    if value_type is None:
        if default is not None:
            value_type = default.__class__
    if subvalue_type is None:
        if default and isinstance(default,(list,tuple)):
            subvalue_type = default[0].__class__

    if value_type is None:
        return value
    elif isinstance(value, value_type):
        return value
    elif issubclass(value_type, list):
        if isinstance(value, tuple):
            return list(value)
        else:
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
        value = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        pass
    except KeyError:
        if default is not None or not required:
            return default
        raise Exception("Missing required environment variable '%s'" % key)

    return _convert(key,value,default=default,required=required,value_type=value_type,subvalue_type=subvalue_type)


url_re = re.compile("^((h|H)(t|T)(t|T)(p|P)(s|S)?://)?(?P<domain>[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*)(:(?P<port>[0-9]+))?(\/|\?|$)")
def get_domain(url):
    if url:
        m = url_re.search(url)
        if m :
            return m.group('domain')
        else:
            return None
    else:
        return None

def get_redirect_domain(request):
    next_url = request.session.get(REDIRECT_FIELD_NAME)
    return get_domain(next_url)

def get_request_domain(request):
    next_url = request.GET.get(REDIRECT_FIELD_NAME)
    if next_url:
        return get_domain(next_url)
    else:
        return request.headers.get("x-upstream-server-name") or request.get_host()


def get_usercache():
    from django.conf import settings
    from django.core.cache import caches
    try:
        if settings.USER_CACHE_ALIAS:
            return caches[settings.USER_CACHE_ALIAS]
        else:
            return None
    except:
        return None


def get_defaultcache():
    from django.conf import settings
    from django.core.cache import caches
    try:
        return caches['default']
    except:
        return None

def get_totpurl(secret, email, issuer, timestep, prefix=None):
    prefix = prefix or issuer

    prefix = urllib.parse.quote(prefix)
    issuer = urllib.parse.quote(issuer)

    if isinstance(secret,bytearray):
        secret = base64.b32encode(secret)
    else:
        secret = base64.b32encode(bytearray(secret,'ascii'))

    return "otpauth://totp/{0}:{1}?secret={2}&period={3}&issuer={0}".format(prefix , email, secret, timestep, issuer)

def encode_qrcode(totpurl):
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_H,
    )
    qr.add_data(totpurl)
    qr.make()
    img = qr.make_image()
    buff = io.BytesIO()
    img.save('data/dst/qrcode_test2_2.png')
    img.save(buff, format="PNG")
    return "data:image/png;base64,"+base64.b64encode(buff.getvalue()).decode("utf-8")


