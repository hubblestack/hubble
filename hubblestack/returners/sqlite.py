# -*- coding: utf-8 -*-
"""
Return hubble data to sqlite (intended for testing)
"""
from functools import wraps
import json
import logging
import os
import hubblestack.returners

IS_CONNECTED = False

try:
    import sqlite3
    HAS_SQLI = True
except Exception:
    HAS_SQLI = False

__virtualname__ = 'sqlite'

log = logging.getLogger(__virtualname__)
if HAS_SQLI:
    version = [int(num) for num in sqlite3.sqlite_version.split('.')]


def __virtual__():
    """
    Return virtual name of the module.

    :return: The virtual name of the module.
    """
    if HAS_SQLI:
        return __virtualname__
    return False, "sqlite3 module is missing"


def _get_options(ret=None):
    """
    Get the sqlite dumpster options from configs
    :return: options
    """

    defaults = {'dumpster': '/var/log/hubblestack/returns.sqlite'}

    attrs = {'dumpster': 'dumpster'}

    _options = hubblestack.returners.get_returner_options(__virtualname__,
                                                   ret,
                                                   attrs,
                                                   __mods__=__mods__,
                                                   __opts__=__opts__,
                                                   defaults=defaults)
    log.debug("_options: %s", _options)
    return _options


def _get_conn():
    """
    Establish a connection (if not connected) and return it

    :return: connection object or None
    """
    global IS_CONNECTED
    _options = _get_options()
    conn = None

    if not IS_CONNECTED:
        database = _options.get('dumpster', 'hubble-returns-testing.db')
        dir = os.path.dirname(database)

        if dir and not os.path.isdir(dir):
            log.debug('creating missing directory %s', dir)
            try:
                os.makedirs(dir, 0o755)
            except OSError:
                log.info('failed to create directory %s', dir)
        try:
            conn = sqlite3.connect(_options.get('dumpster', 'hubble-returns-testing.db'))
            IS_CONNECTED = True
        except sqlite3.Error:
            log.exception('failed to connect to sqlite database %s', database)

        log.debug('creating jid table')

        conn.execute('''CREATE TABLE if not exists jids(jid TEXT PRIMARY KEY, id INT, load TEXT NOT NULL)''')
        if version[0] >= 3 and version[1] >= 9:
            conn.execute('''CREATE TABLE if not exists ret(
            jid TEXT, id INT, fun TEXT, fun_args JSON,
            return_data JSON, FOREIGN KEY(jid) REFERENCES jids(jid))''')
        else:
            conn.execute('''CREATE TABLE if not exists ret(
            jid TEXT,id INT, fun TEXT, fun_args TEXT,
            return_data TEXT,
             FOREIGN KEY(jid) REFERENCES jids(jid))''')

    return conn


def _close_connection(conn):
    '''
    Close sqlite connection
    '''

    global IS_CONNECTED

    if not IS_CONNECTED:
        log.debug('no sqlite connection to close')
        return

    log.debug('closing sqlite connection')
    conn.commit()
    conn.close()

    IS_CONNECTED = False


def _open_close_conn(func):
    '''
    Decorator to open and close sqlite connection
    '''

    @wraps(func)
    def wrapper_func(*args, **kwargs):
        kwargs['conn'] = _get_conn()
        if not kwargs['conn']:
            log.exception('failed to retrieve sqlite connection object')
            return
        results = func(args[0], **kwargs)
        _close_connection(kwargs['conn'])
        return results

    return wrapper_func


@_open_close_conn
def get_fun(fun, fun_args=None, conn=None, return_all=False):
    '''
    Returns load of last function called
    Provide function arguments for a more granular return
    Set return_all to True to return entire query result
    '''

    log.debug('sqlite3 returner get_func called')
    cur = conn.cursor()

    if fun_args:
        log.debug(
            'sqlite3 returner retrieving last job called with function: %s and arguments: %s', fun, fun_args)
        cur.execute('''SELECT jid, id, fun, fun_args, return_data
        FROM jids INNER JOIN ret ON jids.id = ret.id
        WHERE fun_args = ? and fun = ? ORDER BY ret.id DESC ''', fun_args, fun)


@_open_close_conn
def get_ret(conn=None):
    '''
    Returns json of last job called
    '''

    log.debug('sqlite3 returner retrieving last job called')
    cur = conn.cursor()
    cur.execute('''SELECT load FROM jids WHERE id = (SELECT MAX(id) FROM jids)''')
    results = cur.fetchall()
    return results


@_open_close_conn
def get_load(jid, conn=None):
    '''
    Gets load data from the jid specified
    :returns load or None
    '''

    log.debug('sqlite3 returner retrieving data with jid %s', jid)
    cur = conn.cursor()
    cur.execute('''SELECT load FROM jids WHERE jid = ? ''', jid)

    results = cur.fetchall()

    if not results:
        log.debug('failed to return load for jid %s', jid)
        return None

    return results


@_open_close_conn
def _insert_helper(ret, conn=None):
    log.debug('populating jids table with %s', ret.get('jid'))
    ret_jid = ret.get('jid', '') 
    ret_return = ret.get('return', '')
    fun = ret.get('fun', '')
    fun_args = ret.get('fun_args', '')
    conn.execute('''INSERT INTO  jids (id, jid, load)
    VALUES((SELECT IFNULL(MAX(id), 0) + 1 FROM jids),?,?);''', (ret_jid, json.dumps(ret_return)))

    log.debug('populating ret table with jid %s', ret_jid)
    conn.execute('''INSERT INTO  ret (id, jid, fun, fun_args, return_data)
    VALUES((SELECT IFNULL(MAX(id), 0) + 1 FROM ret),?,?,?,?);''',
                 (ret_jid, fun, fun_args, json.dumps(ret_return)))


def _insert(ret, conn=None):
    # identify lists of events
    list_of_events = False
    if isinstance(ret, (list, tuple)):
        num_events = sum([0 if isinstance(i, dict) else 1 for i in ret])
        if num_events == 0:
            list_of_events = True

    # recursion
    if list_of_events:
        for item in ret:
            _insert(item)
        return

    for key in list(ret):
        if not ret[key]:
            ret.pop(key)
        if version[0] >= 3 and version[1] >= 9:
            if isinstance(ret.get(key), (list, tuple, dict)):
                ret[key] = json.dumps(ret[key])

    _insert_helper(ret, conn)


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


def returner(ret):
    """
    The main returner function that sends ret data to sqlite
    """
    _insert(ret)
