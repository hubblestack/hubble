# -*- coding: utf-8 -*-
"""
Return hubble data to sqlite (intended for testing)
"""


import json
import logging
import os
import salt.returners

try:
    import sqlite3

    GOT_SQLI = True
except Exception:
    GOT_SQLI = False

__virtualname__ = 'sqlite'

log = logging.getLogger(__virtualname__)

_CONN = None


def __virtual__():
    """
    Return virtual name of the module.

    :return: The virtual name of the module.
    """
    if GOT_SQLI:
        return __virtualname__
    return False, "sqlite3 module is missing"


def _get_options(ret=None):
    """
    Get the sqlite dumpster options from configs

    :return: options
    """

    defaults = {'dumpster': '/var/log/hubblestack/returns.sqlite'}

    attrs = {'dumpster': 'dumpster'}

    _options = salt.returners.get_returner_options(__virtualname__,
                                                   ret,
                                                   attrs,
                                                   __salt__=__salt__,
                                                   __opts__=__opts__,
                                                   defaults=defaults)
    log.debug("_options: %s", _options)
    return _options


def _get_conn():
    """
    Establish a connection (if not connected) and return it

    :return: connection
    """
    _options = _get_options()
    global _CONN
    if not _CONN:
        _p = _options.get('dumpster', 'hubble-returns.db')
        _d = os.path.dirname(_p)
        if _d and not os.path.isdir(_d):
            log.debug('creating directory %s', _d)
            os.makedirs(_d, 0o755)
        log.debug('connecting to database in %s', _p)
        _CONN = sqlite3.connect(_options.get('dumpster', 'hubble-returns.db'))
        log.debug('creating ret table')
        _CONN.execute('''create table if not exists ret(
            jid text, id text, fun text, fun_args json,
            ret json)''')
    return _CONN


"""
##### just for reference
## {u'fun': u'hubble.audit',
##  u'fun_args': [u'cve.scan-v2'],
##  u'id': u'hostname.here',
##  u'jid': u'20180117091736565184',
##  u'return': {u'Compliance': u'0%',
##   u'Failure': [{u'ruby2.3-2.3.3-2~16.04.5': u'Ruby vulnerabilities'},
##    {u'libjavascriptcoregtk-4.0-18-2.18.5-0ubuntu0.16.04.1': u'WebKitGTK+ vulnerabilities'},
##    {u'libwebkit2gtk-4.0-37-2.18.5-0ubuntu0.16.04.1': u'WebKitGTK+ vulnerabilities'},
##    {u'libruby2.3-2.3.3-2~16.04.5': u'Ruby vulnerabilities'},
##    {u'linux-image-generic-4.4.0.109.114': u'Linux kernel regression'},
##    {u'libgdk-pixbuf2.0-0-2.32.2-1ubuntu1.4': u'GDK-PixBuf vulnerabilities'}],
##   u'Success': []}}
"""


def _put(ret):
    """
    Add item to sqlite
    """
    conn = _get_conn()

    # identify lists of events
    list_of_events = False
    if isinstance(ret, (list, tuple)):
        num_events = sum([0 if isinstance(i, dict) else 1 for i in ret])
        if num_events == 0:
            list_of_events = True

    if list_of_events:
        for item in ret:
            _put(item)
        return

    for item in ret:
        if isinstance(ret[item], (list, tuple, dict)):
            ret[item] = json.dumps(ret[item])

    # try to get sqlite queries to show not-ints for jids
    ret['jid'] = str(ret.get('jid', '??'))
    log.info("logging jid=%s in sqlite dumpster", **ret)

    for i in ('id', 'fun', 'fun_args', 'return', 'Failure', 'Success'):
        if i not in ret:
            ret[i] = None
    # conn.execute("insert into ret values(:jid,:id,:fun,json(:fun_args),json(:return))", x)
    # json() isn't added until later than sqlite-3.7.17 (the centos7 version)...
    conn.execute("insert into ret values(:jid,:id,:fun,:fun_args,:return)", ret)
    conn.commit()


def returner(ret):
    """
    The main returner function that sends ret data to sqlite
    """
    _put(ret)
