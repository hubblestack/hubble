# -*- encoding: utf-8 -*-
'''
Flexible Data Gathering: osquery
================================

This fdg module allows for running osquery queries
'''
from __future__ import absolute_import
import json
import logging
import os

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def query(query_sql, osquery_args=None, osquery_path=None, format_chained=True, chained=None, chained_status=None):
    '''
    Given an osquery query ``query_sql``, run that query.

    By default, the ``query_sql`` will have ``.format()`` called on it with
    ``chained`` as the only argument. (So, use ``{0}`` in your query to
    substitute the chained value.) If you want to avoid having to escape
    curly braces, set ``format_chained=False``.

    The first return value (status) will be True if the osquery retcode is 0,
    and False othewise. The second argument will be the output of the
    ``osquery`` command.

    query_sql
        The query to be run

    osquery_args
        Optional argument with a string of args to pass to osquery. Note that
        the ``--read_max`` and ``--json`` args are already included.

    osquery_path
        Optional argument to specify a specific path to the osquery binary

    format_chained
        Whether to call ``.format(chained)`` on the query. Defaults to True.
        Set to False if you want to avoide having to escape curly braces.

    chained
        The value chained from the previous call.
    '''
    if format_chained:
        query_sql = query_sql.format(chained)
    if osquery_args is None:
        osquery_args = []
    return _osquery(query_sql, args=osquery_args, osquery_path=osquery_path)

    return _osquery(query_sql, args=osquery_args, osquery_path=osquery_path)

def _osquery(query_sql, osquery_path=None, args=None):
    """
    Format the osquery command and run it

    Returns a tuple, (status, ret) where status is True if the retcode is 0,
    False otherwise, and ``ret`` is the stdout of the osquery command
    """
    MAX_FILE_SIZE = 104857600
    if not query_sql:
        return False, ''
    if 'attach' in query_sql.lower() or 'curl' in query_sql.lower():
        log.critical('Skipping potentially malicious osquery query \'{0}\' '
                     'which contains either \'attach\' or \'curl\': {1}'
                     .format(name, query_sql))
        return False, ''

    # Run the osqueryi query
    query_ret = {
        'result': True,
    }

    # Prep the command
    if not osquery_path:
        if not os.path.isfile(__grains__['osquerybinpath']):
            log.error('osquery binary not found: {0}'.format(__grains__['osquerybinpath']))
            return False, ''
        cmd = [__grains__['osquerybinpath'], '--read_max', MAX_FILE_SIZE, '--json', query_sql]
    else:
        if not os.path.isfile(osquery_path):
            log.error('osquery binary not found: {0}'.format(osquery_path))
            return False, ''
        cmd = [osquery_path, '--read_max', MAX_FILE_SIZE, '--json', query_sql]
    if isinstance(args, (list,tuple)):
        cmd.extend(args)

    # Run the command
    res = __salt__['cmd.run_all'](cmd, timeout=10000, python_shell=False)

    if res['retcode'] == 0:
        ret = json.loads(res['stdout'])
        for result in ret:
            for key, value in result.iteritems():
                if value and isinstance(value, basestring) and value.startswith('__JSONIFY__'):
                    result[key] = json.loads(value[len('__JSONIFY__'):])
        return True, ret
    else:
        return False, res['stdout']
