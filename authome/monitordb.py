import re
import logging

from django.db import connections
from django.utils import timezone
from django.conf import settings
from django.db.backends.signals import connection_created

from . import utils

logger = logging.getLogger(__name__)

if settings.DB_TRAFFIC_MONITOR_LEVEL > 0:
    _cache = None
    select_re = re.compile('select\\s.+\\sfrom\\s+("?[a-zA-Z0-9\\-_]+"?\\.)?"?(?P<table>[a-zA-Z0-9\\-_]+)"?',re.I|re.M|re.S)
    delete_re = re.compile('delete\\s+from\\s+("?[a-zA-Z0-9\\-_]+"?\\.)?"?(?P<table>[a-zA-Z0-9\\-_]+)"?',re.I|re.M|re.S)
    update_re = re.compile('update\\s+("?[a-zA-Z0-9\\-_]+"?\\.)?"?(?P<table>[a-zA-Z0-9\\-_]+)"?',re.I|re.M|re.S)
    insert_re = re.compile('insert\\s+into\\s+("?[a-zA-Z0-9\\-_]+"?\\.)?"?(?P<table>[a-zA-Z0-9\\-_]+)"?',re.I|re.M|re.S)
    savepoint_re = re.compile('\\s*(RELEASE\\s+)?SAVEPOINT\\s+',re.I|re.M|re.S)

    def monitor_db_access(execute, sql, params, many, context):
        global _cache
        try:
            starttime = timezone.localtime()
            status = "OK"
            return execute(sql, params, many, context)
        except Exception as ex:
            status = ex.__class__.__name__
            raise
        finally:
            #cache and ignore the exceptions which are thrown before cache is fully initialized
            try:
                if settings.DB_TRAFFIC_MONITOR_LEVEL == 1:
                    _cache.log_dbrequest("DB",None,starttime,status)
                else:
                    m = select_re.search(sql)
                    if m:
                        _cache.log_dbrequest("DB","SELECT {}".format(m.group("table").lower()),starttime,status)
                    elif sql == utils.ping_db_sql:
                        _cache.log_dbrequest("DB","PING",starttime,status)
                    else:
                        m = savepoint_re.search(sql)
                        if not m:
                            m = update_re.search(sql)
                            if m:
                                _cache.log_dbrequest("DB","UPDATE {}".format(m.group("table").lower()),starttime,status)
                            else:
                                m = insert_re.search(sql)
                                if m:
                                    _cache.log_dbrequest("DB","INSERT {}".format(m.group("table").lower()),starttime,status)
                                else:
                                    m = delete_re.search(sql)
                                    if m:
                                        _cache.log_dbrequest("DB","DELETE {}".format(m.group("table").lower()),starttime,status)
                                    else:
                                        _cache.log_dbrequest("DB","OTHERS",starttime,status)
            except:
                try:
                    from . import cache
                    _cache = cache.cache
                except:
                    _cache = None
    
    def install_monitor_db_access(connection, **kwargs):
        """
        Install monitor_db_access on the given database connection.
        Rather than use the documented API of the `execute_wrapper()` context
        manager, directly insert the hook.
        """
        
        if monitor_db_access in connection.execute_wrappers:
            return

        connection.execute_wrappers.insert(0, monitor_db_access)
    
    
    for connection in connections.all():
        install_monitor_db_access(connection=connection)

    connection_created.connect(install_monitor_db_access)
