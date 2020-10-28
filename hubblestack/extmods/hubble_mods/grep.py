# -*- encoding: utf-8 -*-
"""
Module for running grep command. Same can be used in both Audit/FDG

Audit Example:
---------------
check_unique_id:
  description: 'grep check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: grep
      items:
        - args:
            path: /etc/ssh/ssh_config
            pattern: '"^host"'
            flags: '-E'
          comparator:
            type: "string"
            match: "host*"
            is_regex: true

FDG Example:
------------
main:
  description: 'grep check'
  module: grep
  args:
    path: /etc/ssh/ssh_config
    pattern: 'host'
Mandatory parameters:
    path - file path
Multiple paths can be provided in a single implementation under attribute: "items"

Note: Comparison logic is moved to comparators. Module will just invoke the grep command.
Comparator compatible with this module - string

Sample Output:
'Thus, host-specific definitions should be at the beginning of the\n#   RhostsRSAAuthentication no'

Note: In normal execution, this module expects a filepath. In case of chaining, it expects a string from chaining
"""

import os
import logging

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError
from salt.exceptions import CommandExecutionError

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
        Example: {'chaining_args': {'result': "/some/path/file.txt", 'status': True},
                  'caller': 'Audit'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: grep Start validating params for check-id: {0}'.format(block_id))

    error = {}
    # fetch required param
    file_content = runner_utils.get_chained_param(extra_args)
    filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    if not file_content and not filepath:
        error['path'] = 'Mandatory parameter: path not found for id: %s' % (block_id)

    pattern_val = runner_utils.get_param_for_module(block_id, block_dict, 'pattern')
    if not pattern_val:
        error['pattern'] = 'Mandatory parameter: pattern not found for id: %s' % (block_id)

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "/some/path/file.txt", 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing grep module for id: {0}'.format(block_id))
    # default mode=file, search in file.
    # In chaining, this will search in chained content
    file_mode = True
    filepath = None

    # check if chained content is available
    file_content = runner_utils.get_chained_param(extra_args)
    if file_content:
        file_mode = False
        format_chained = runner_utils.get_param_for_module(block_id, block_dict, 'format_chained', True)
        starting_string = runner_utils.get_param_for_module(block_id, block_dict, 'starting_string', False)
        if format_chained and starting_string:
            file_content = starting_string.format(file_content)
    # fetch required param
    if file_mode:
        filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    pattern = runner_utils.get_param_for_module(block_id, block_dict, 'pattern')
    flags = runner_utils.get_param_for_module(block_id, block_dict, 'flags')
    if flags is None:
        flags = []
    if isinstance(flags, str):
        flags = [flags]

    # check filepath existence
    if file_mode and not os.path.isfile(filepath):
        return runner_utils.prepare_negative_result_for_module(block_id, 'file_not_found')

    grep_result = _grep(filepath, file_content, pattern, *flags)
    ret_code = grep_result.get('retcode')
    result = grep_result.get('stdout')
    if ret_code != 0:
        if ret_code == 1:
            return runner_utils.prepare_negative_result_for_module(block_id, "pattern_not_found")
        else:
            return runner_utils.prepare_negative_result_for_module(block_id, "non_zero_return_code")

    return runner_utils.prepare_positive_result_for_module(block_id, result)


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': "/some/path/file.txt", 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    filepath = runner_utils.get_chained_param(extra_args)
    if not filepath:
        filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    pattern = runner_utils.get_param_for_module(block_id, block_dict, 'pattern')

    return {'path': filepath,
            'pattern': pattern}


def _grep(path,
          string,
          pattern,
          *args
          ):
    """
    Grep for a string in the specified file

    .. note::
        This function's return value is slated for refinement in future
        versions of Salt

    path
        Path to the file to be searched

        .. note::
            Globbing is supported (i.e. ``/var/log/foo/*.log``, but if globbing
            is being used then the path should be quoted to keep the shell from
            attempting to expand the glob expression.

    string
        String to search (Only used while chaining)

    pattern
        Pattern to match. For example: ``test``, or ``a[0-5]``

    args
        Additional command-line flags to pass to the grep command. For example:
        ``-v``, or ``-i -B2``
    """
    if path:
        path = os.path.expanduser(path)

    if args:
        options = [' '.join(args)]
    else:
        options = []
    
    # prepare the command
    cmd = ['grep'] + options + [pattern]
    if path:
        cmd += [path]

    try:
        ret = __salt__['cmd.run_all'](cmd, python_shell=False, ignore_retcode=True, stdin=string)
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return ret
