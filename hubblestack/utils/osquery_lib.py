"""
HubbleStack osquery lib. Can be used to execute osquery queries from Hubble code
Author - Mudit Agarwal (muagarwa@adobe.com)
"""
import logging
import os
import salt.modules.cmdmod
import json

__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet,
            'cmd.run_all': salt.modules.cmdmod.run_all}

log = logging.getLogger(__name__)

def query(query_sql='', osquery_path='/opt/osquery/osqueryi', args=None, max_file_size=104857600, timeout=10000, output_loglevel='quiet'):
  try:
    if not query_sql:
      return None
    if 'attach' in query_sql.lower() or 'curl' in query_sql.lower():
        log.critical('Skipping potentially malicious osquery query '
                     'which contains either \'attach\' or \'curl\': {0}'
                     .format(query_sql))
        return None
    if not os.path.isfile(osquery_path):
      log.error('osquery binary not found: %s', osquery_path)
      return None
    else:
      cmd = [osquery_path, '--read_max', max_file_size, '--json', query_sql]
    if isinstance(args, (list, tuple)):
      cmd.extend(args)

    # Run the command

    res = __salt__['cmd.run_all'](cmd, timeout=timeout, python_shell=False, output_loglevel=output_loglevel)
    if res['retcode'] == 0:
      ret = json.loads(res['stdout'])
      return ret
    return None
  except Exception as e:
    log.exception('An exception occurred while executing query {0} - {1}'.format(query_sql, e))
    return None
