import threading
import logging
import socket
import os
import psutil
from datetime import datetime

from django.core.signals import request_started,request_finished
from django.http import JsonResponse
from django.dispatch import receiver
from django.utils import timezone

logger = logging.getLogger(__name__)

_processing_info = threading.local()

processcreatetime = timezone.make_aware(datetime.fromtimestamp(psutil.Process(os.getpid()).create_time())).strftime("%Y-%m-%d %H:%M:%S.%f")
processname = "{}-{}-{}".format(socket.gethostname(),processcreatetime,os.getpid())
print("process createtime = {}".format(processcreatetime))

def _get_processingstep(index):
    if not index:
        return  _processing_info.steps
    else:
        step = None
        for i in index:
            if not step:
                step = _processing_info.steps[i]
            else:
                step = step[4][i]
        return step

def start_processingstep(stepname):
    if not _processing_info.enabled:
        return

    new_step = [stepname,timezone.localtime(),None,None,[]]
    if not _processing_info.index:
        _processing_info.steps.append(new_step)
        _processing_info.index.append(0)
    else:
        c_step = _get_processingstep(_processing_info.index)
        if c_step[2]:
            raise Exception("The processing step({0}) can't be started in a finished step({1})".format(stepname,c_step[0]))
        else:
            c_step[4].append(new_step)
            _processing_info.index.append(len(c_step[4]) - 1)

def end_processingstep(stepname):
    if not _processing_info.enabled:
        return

    c_step = _get_processingstep(_processing_info.index)
    if c_step[0] == stepname:
        c_step[2] = timezone.localtime()
        del _processing_info.index[-1]
    else:
        raise Exception("End processing step({0}) can't match the current process step({1})".format(stepname,c_step[0]))
    

def request_received():
    _processing_info.steps = []
    _processing_info.index = []

    start_processingstep("requestprocessing")
    

@receiver(request_started)
def request_start(sender, **kwargs):
    if kwargs["environ"].get("PATH_INFO","").endswith("performance"):
        _processing_info.enabled = True
        request_received()
    else:
        _processing_info.enabled = False

    

def get_processingsteps():
    if not _processing_info.enabled:
        return []

    steps = _processing_info.steps
    #add a preprocess step 
    steps[0][4].insert(0,["preprocessing",steps[0][1],steps[0][4][0][1],None,[]])
    steps = format_processingsteps(steps)
    return steps

def format_processingsteps(steps):
    if not steps:
        return steps

    for step in steps:
        step[3] = "{} milliseconds".format(round((step[2] - step[1]).total_seconds() * 1000,2))
        step[1] = step[1].strftime("%Y-%m-%d %H:%M:%S.%f")
        step[2] = step[2].strftime("%Y-%m-%d %H:%M:%S.%f")
        format_processingsteps(step[4])

    return steps

def parse_datetime(dt):
    return timezone.make_aware(datetime.strptime(dt,"%Y-%m-%d %H:%M:%S.%f"))
 
def parse_processingsteps(steps):
    if not steps:
        return  steps

    for step in steps:
        step[1] = timezone.localtime(timezone.make_aware(datetime.strptime(step[1],"%Y-%m-%d %H:%M:%S.%f")))
        step[2] = timezone.localtime(timezone.make_aware(datetime.strptime(step[2],"%Y-%m-%d %H:%M:%S.%f")))
        parse_processingsteps(step[4])

    return steps

def performancetester_wrapper(func):
    def _process(*args,**kwargs):
        res = func(*args,**kwargs)
        end_processingstep("requestprocessing")
        data =  {
            "status_code":res.status_code,
            "processingsteps":get_processingsteps(),
            "processname":processname,
            "processcreatetime":processcreatetime
        }
        return JsonResponse(data,status=200)

    return _process
