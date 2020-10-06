# -*- encoding: utf-8 -*-
"""
Module for running stat command. Same can be used in both Audit/FDG

Audit Example:
---------------
check_unique_id:
  description: 'stat check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      module: stat
      items:
        - args:
            path: /etc/ssh/ssh_config1

FDG Example:
------------
main:
  description: 'stat check'
  module: stat
  args:
    path: /etc/ssh/ssh_config1

Mandatory parameters:
    path - file path
Multiple paths can be provided in a single implementation under attribute: "items"

Note: Comparison logic is moved to comparators. Module will just invoke the stat command.
Comparator compatible with this module - dict

Sample Output:
{
  'inode': 34881435,
  'uid': 0,
  'gid': 0,
  'group': 'root',
  'user': 'root',
  'atime': 1598525499.6568148,
  'mtime': 1598521394.6416965,
  'ctime': 1598525484.2277226,
  'size': 373,
  'mode': '0666',
  'type': 'file',
  'target': '/hubble_build/pytest.ini'
}
"""

import os
import logging

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

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
    log.debug('Module: stat Start validating params for check-id: {0}'.format(block_id))

    #fetch required param
    filepath = runner_utils.get_chained_param(chain_args)
    if not filepath:
        filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')

    if not filepath:
        raise HubbleCheckValidationError('Mandatory parameter: {0} not found for id: {1}'.format('path', block_id))

    log.debug('Validation success for check-id: {0}'.format(block_id))

def execute(block_id, block_dict, chain_args=None):
    """
    Execute the module

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
    log.debug('Executing stat module for id: {0}'.format(block_id))

    #fetch required param
    filepath = runner_utils.get_chained_param(chain_args)
    if not filepath:
        filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')

    # check filepath existence
    if not os.path.isfile(filepath):
        return runner_utils.prepare_negative_result_for_module(block_id, 'file_not_found')

    stat_res = __salt__['file.stats'](filepath)
    return runner_utils.prepare_positive_result_for_module(block_id, stat_res)

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

    #fetch required param
    filepath = runner_utils.get_chained_param(chain_args)
    if not filepath:
        filepath = runner_utils.get_param_for_module(block_id, block_dict, 'path')
    return {'path': filepath}
