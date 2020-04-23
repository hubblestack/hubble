import logging
import os
import salt.modules.cmdmod
import json

__salt__ = {'cmd.run': salt.modules.cmdmod._run_quiet,
            'cmd.run_all': salt.modules.cmdmod.run_all}

log = logging.getLogger(__name__)

def query(query_sql='', osquery_path=None, args=None, max_file_size=104857600, timeout=10000, output_loglevel='quiet'):
  try:
    if not query_sql:
      return None
    if not osquery_path:
      if not os.path.isfile(__grains__['osquerybinpath']):
        log.error('osquery binary not found: %s', __grains__['osquerybinpath'])
        return None
      cmd = [__grains__['osquerybinpath'], '--read_max', max_file_size, '--json', query_sql]
    else:
      if not os.path.isfile(osquery_path):
        log.error('osquery binary not found: %s', osquery_path)
        return None
      cmd = [osquery_path, '--read_max', max_file_size, '--json', query_sql]
    if isinstance(args, (list, tuple)):
      cmd.extend(args)

    # Run the command

    res = __salt__['cmd.run_all'](cmd, timeout=timeout, python_shell=False, output_loglevel=output_loglevel)
    if res['retcode'] == 0:
      ret = json.loads(res['stdout'])
      if len(ret) != 0:
        for result in ret:
          for key, value in result.items():
            if value and isinstance(value, unicode):
              return value
    return None
  except Exception as e:
    log.exception('An exception occurred while executing query {0} - {1}'.format(query_sql, e))
    return None
