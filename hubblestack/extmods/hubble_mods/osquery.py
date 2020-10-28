'''
Flexible Data Gathering: osquery

This module allows for running osquery queries

Mandatory param:
    query -  The query which needs to be run

Optional param:
    cast_to_string - Default (False) - Specifies if the command output (ex. list of dictionaries)  needs to be type cast to string

    flags - string of osquery args to pass to osquery. Note that the ``--read_max`` and ``--json`` args are already included.

    osquery_path - specific path to the osquery binary

    format_chained - Default (True) - Whether to call ``.format(chained)`` on the query. Set to False if you want to avoid having to escape curly braces.

Audit Example:
---------------
check_unique_id:
  description: 'osquery check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: osquery
      items:
        - args:
            query: 'SELECT t.unix_time AS query_time, os.* FROM os_version AS os LEFT JOIN time AS t;'
          comparator:
            type: list
            match_any:
              - name: CentOS Linux
                platform: rhel


FDG Example:
------------
main:
  description: 'osquery check'
  module: osquery
    args:
      query: 'SELECT t.unix_time AS query_time, os.* FROM os_version AS os LEFT JOIN time AS t;'

Mandatory Params:
    This module requires query. That come either from args, or from chaining, or both


Output:
The return value will be  a tuple (True, Result) if the osquery return code is 0 otherwise (False, Result).
The second argument will be the result of the ``osquery`` command.
'''

import json
import logging
import os

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)


def validate_params(block_id, block_dict, extra_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': [{'name': 'CentOS Linux', 'platform': 'rhel', 'version': 'CentOS Linux release 7.8.2003 (Core)'}], 'status': True},
                  'caller': 'FDG'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: osquery Start validating params for check-id: {0}'.format(block_id))

    query = runner_utils.get_param_for_module(block_id, block_dict, 'query')

    if not query:
        raise HubbleCheckValidationError('Mandatory parameter: {0} not found for id: {1}'.format('query', block_id))

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, extra_args=None):
    """
    Execute the osquery module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': [{'name': 'CentOS Linux', 'platform': 'rhel', 'version': 'CentOS Linux release 7.8.2003 (Core)'}], 'status': True},
                  'caller': 'FDG'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing osquery module for id: {0}'.format(block_id))

    chained_param = runner_utils.get_chained_param(extra_args)
    # fetch required param
    query = runner_utils.get_param_for_module(block_id, block_dict, 'query')

    # fetch optional param
    format_chained = runner_utils.get_param_for_module(block_id, block_dict, 'format_chained', True)
    flags = runner_utils.get_param_for_module(block_id, block_dict, 'flags')
    osquery_path = runner_utils.get_param_for_module(block_id, block_dict, 'osquery_path')
    cast_to_string = runner_utils.get_param_for_module(block_id, block_dict, 'cast_to_string', False)

    if format_chained and chained_param:
        query = query.format(chained_param)
    if flags is None:
        flags = []

    return _osquery(block_id, query, args=flags, osquery_path=osquery_path, cast_to_string=cast_to_string)


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': [{'name': 'CentOS Linux', 'platform': 'rhel', 'version': 'CentOS Linux release 7.8.2003 (Core)'}], 'status': True},
                  'caller': 'FDG'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    chained_param = runner_utils.get_chained_param(extra_args)
    query = runner_utils.get_param_for_module(block_id, block_dict, 'query')
    format_chained = runner_utils.get_param_for_module(block_id, block_dict, 'format_chained', True)
    if format_chained and chained_param:
        query = query.format(chained_param)
    return {'query': query}


def _osquery(block_id, query, osquery_path=None, args=None, cast_to_string=None):
    """
    Format the osquery command and run it

    Returns a tuple, (status, ret) where status is True if the return code is 0,
    False otherwise, and ``ret`` is the stdout of the osquery command
    """
    max_file_size = 104857600

    if not query:
        return runner_utils.prepare_negative_result_for_module(block_id, 'Empty query passed')
    if 'attach' in query.lower() or 'curl' in query.lower():
        log.critical('Skipping potentially malicious osquery query \'%s\' '
                     'which contains either \'attach\' or \'curl\'', query)
        return runner_utils.prepare_negative_result_for_module(block_id, 'Curl/Attach passed in query')

    # Prep the command
    if not osquery_path:
        if not os.path.isfile(__grains__['osquerybinpath']):
            log.error('osquery binary not found: %s', __grains__['osquerybinpath'])
            return runner_utils.prepare_negative_result_for_module(block_id, 'osquery binary not found')
        cmd = [__grains__['osquerybinpath'], '--read_max', max_file_size, '--json', query]
    else:
        if not os.path.isfile(osquery_path):
            log.error('osquery binary not found: %s', osquery_path)
            return runner_utils.prepare_negative_result_for_module(block_id, 'osquery binary not found')
        cmd = [osquery_path, '--read_max', max_file_size, '--json', query]
    if isinstance(args, (list, tuple)):
        cmd.extend(args)

    # Run the command
    res = __salt__['cmd.run_all'](cmd, timeout=10000, python_shell=False)
    if res['retcode'] == 0:
        ret = json.loads(res['stdout'])
        for result in ret:
            for key, value in result.items():
                if value and isinstance(value, str) and value.startswith('__JSONIFY__'):
                    result[key] = json.loads(value[len('__JSONIFY__'):])
        if cast_to_string:
            try:
                ret = _convert_to_str(ret)
            except (KeyError, TypeError):
                log.error('Invalid data type returned by osquery call %s.', res, exc_info=True)
                return runner_utils.prepare_negative_result_for_module(block_id, 'Error while casting to string')
        return runner_utils.prepare_positive_result_for_module(block_id, ret)

    return runner_utils.prepare_negative_result_for_module(block_id, res['stdout'])


def _convert_to_str(data):
    """
    Convert list of dicts containing items as unicode or other data type to str.

    process_data
        input list of dicts to convert to str
    """
    if not data:
        return None
    ret = []
    try:
        for process in data:
            str_process = {str(name): str(val) for name, val in process.items()}
            ret.append(str_process)
    except (TypeError, AttributeError):
        log.error('Invalid argument type; must be list of dicts.', exc_info=True)
        return None

    return ret