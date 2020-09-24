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
            file: /etc/ssh/ssh_config
            pattern: '"^host"'
            flags: '-E'

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
"""

import os
import logging

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError
from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def validate_params(block_id, block_dict, chain_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param chain_args:
        Chained argument dictionary, (If any)
        Example: {'result': "/some/path/file.txt", 'status': True}

    Raises:
        AuditCheckValidationError: For any validation error
    """
    log.debug('Module: grep Start validating params for check-id: {0}'.format(block_id))

    # fetch required param
    mandatory_params = ['file', 'pattern']
    error = {}
    for param in mandatory_params:
        param_val = runner_utils.get_param_for_module(block_id, block_dict, param, chain_args)
        if not param_val:
            error[param] = 'Mandatory parameter: %s not found for id: %s' % (param, block_id)

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, chain_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param chain_args:
        Chained argument dictionary, (If any)
        Example: {'result': "/some/path/file.txt", 'status': True}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing grep module for id: {0}'.format(block_id))

    # fetch required param
    filepath = runner_utils.get_param_for_module(block_id, block_dict, 'file', chain_args)
    pattern = runner_utils.get_param_for_module(block_id, block_dict, 'pattern', chain_args)
    flags = runner_utils.get_param_for_module(block_id, block_dict, 'flags', chain_args)
    if flags is None:
        flags = []
    if isinstance(flags, str):
        flags = [flags]

    # check filepath existence
    if not os.path.isfile(filepath):
        return runner_utils.prepare_negative_result_for_module(block_id, 'file_not_found')

    grep_result = _grep(filepath, pattern, *flags)
    ret_code = grep_result.get('retcode')
    result = grep_result.get('stdout')
    if ret_code != 0:
        return runner_utils.prepare_negative_result_for_module(block_id, "non_zero_return_code")

    return runner_utils.prepare_positive_result_for_module(block_id, result)


def get_filtered_params_to_log(block_id, block_dict, chain_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param chain_args:
        Chained argument dictionary, (If any)
        Example: {'result': "/some/path/file.txt", 'status': True}
    """
    log.debug('get_filtered_params_to_log for id: {0}'.format(block_id))

    # fetch required param
    file = runner_utils.get_param_for_module(block_id, block_dict, 'file', chain_args)
    pattern = runner_utils.get_param_for_module(block_id, block_dict, 'pattern', chain_args)

    return {'file': file,
            'pattern': pattern}


def _grep(path,
          pattern,
          *args):
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

    pattern
        Pattern to match. For example: ``test``, or ``a[0-5]``

    args
        Additional command-line flags to pass to the grep command. For example:
        ``-v``, or ``-i -B2``
    """
    path = os.path.expanduser(path)

    if args:
        options = ' '.join(args)
    else:
        options = ''
    cmd = (
        r'''grep  {options} {pattern} {path}'''
            .format(
            options=options,
            pattern=pattern,
            path=path,
        )
    )

    try:
        ret = __salt__['cmd.run_all'](cmd, python_shell=False, ignore_retcode=True)
    except (IOError, OSError) as exc:
        raise CommandExecutionError(exc.strerror)

    return ret
