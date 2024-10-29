import json
from datetime import datetime,date,timedelta

from django.utils import timezone

class Formatable(object):
    def format(self):
        return self.__repr__()

class Processtime(Formatable):
    def __init__(self,val):
        self.val = val
    def __repr__(self):
        return "{:.6f}".format(self.val)

class JSONDecoder(json.JSONDecoder):

    def __init__(self,*args, **kwargs):
        kwargs["object_hook"] = self.dict_to_object
        json.JSONDecoder.__init__(self, *args, **kwargs)
    
    def dict_to_object(self, d): 
        if '__type__' not in d:
            return d

        if d["__type__"] == "datetime":
            return timezone.localtime(timezone.make_aware(datetime.strptime(d["value"],"%Y-%m-%dT%H:%M:%S.%f"),timezone=timezone.utc))
        elif d["__type__"] == "date":
            return date(*d["value"])
        elif d["__type__"] == "timedelta":
            return timedelta(*d["value"])
        else:
            return d

class JSONEncoder(json.JSONEncoder):
    """ Instead of letting the default encoder convert datetime to string,
        convert datetime objects into a dict, which can be decoded by the
        DateTimeDecoder
    """
        
    def default(self, obj):
        if isinstance(obj, datetime):
            return {
                '__type__' : 'datetime',
                'value' : timezone.localtime(obj,timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
            }   
        elif isinstance(obj, date):
            return {
                '__type__' : 'date',
                'value' : [obj.year,obj.month,obj.day]
            }   
        elif isinstance(obj, timedelta):
            return {
                '__type__' : 'timedelta',
                'value' : [obj.days,obj.seconds,obj.microseconds]
            }   
        else:
            return super().default(obj)

class JSONFormater(json.JSONEncoder):
    """ Instead of letting the default encoder convert datetime to string,
        convert datetime objects into a dict, which can be decoded by the
        DateTimeDecoder
    """
        
    def default(self, obj):
        if isinstance(obj, datetime):
            return timezone.localtime(obj).strftime("%Y-%m-%dT%H:%M:%S.%f")
        elif isinstance(obj, date):
            return obj.strftime(obj,"%Y-%m-%d")
        elif isinstance(obj, timedelta):
            return "{}.{}".format(obj.days * 86400 + obj.seconds,obj.microseconds)
        elif isinstance(obj, Formatable):
            return obj.format()
        else:
            return super().default(obj)
