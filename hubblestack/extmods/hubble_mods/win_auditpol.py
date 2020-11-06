# -*- encoding: utf-8 -*-
"""
Module for fetching audit policies values using auditpol command
Audit Example 1:
---------------
check_unique_id:
  description: 'win_auditpol check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:Microsoft Windows Server 2016*'
      hubble_version: '>3 AND <7 AND <8'
      module: win_auditpol
      items:
        - args:
            name: 'Distribution Group Management'
          comparator:
            type: "dict"
            match:
              'Distribution Group Management': 'Success and Failure'


FDG Example:
------------
main:
  description: 'win_auditpol fdg'
  module: win_auditpol
  args:
    name: 'Distribution Group Management'
Mandatory parameters:
    name - the name of the audit policy

Note: Comparison logic is moved to comparators. Module will just invoke the auditpol command.
Comparator compatible with this module - dict
Sample Output:
    {'Distribution Group Management': 'Success and Failure'}
"""

import csv
import logging
import salt.utils.platform

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError

log = logging.getLogger(__name__)


def __virtual__():
    if not salt.utils.platform.is_windows():
        return False, 'This audit module only runs on windows'
    return True


def validate_params(block_id, block_dict, extra_args=None):
    """
    Validate all mandatory params required for this module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': 'Distribution Group Management', 'status': True},
                  'caller': 'Audit'}

    Raises:
        HubbleCheckValidationError: For any validation error
    """
    log.debug('Module: win_auditpol. Start validating params for check-id: {0}'.format(block_id))
    error = {}
    chained_name = runner_utils.get_chained_param(extra_args)
    name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    # fetch required param
    if not name and not chained_name:
        error['name'] = 'Mandatory parameter: name not found for id: %s' % block_id

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def execute(block_id, block_dict, extra_args=None):
    """
    Execute the module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': 'Distribution Group Management', 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing win_auditpol module for id: {0}'.format(block_id))
    # fetch required param
    name = runner_utils.get_chained_param(extra_args)
    if not name:
        name = runner_utils.get_param_for_module(block_id, block_dict, 'name')

    __auditdata__ = _auditpol_import()
    if name in __auditdata__:
        audit_value = __auditdata__[name]
        return runner_utils.prepare_positive_result_for_module(block_id, {name: audit_value})

    return runner_utils.prepare_negative_result_for_module(block_id, 'policy_not_found')


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': 'Distribution Group Management', 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('Module: win_auditpol get_filtered_params_to_log for id: {0}'.format(block_id))
    # fetch required param
    name = runner_utils.get_chained_param(extra_args)
    if not name:
        name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    return {'name': name}


def _auditpol_import():
    dict_return = {}
    export = _auditpol_export()
    auditpol_csv = csv.DictReader(export)
    for row in auditpol_csv:
        if row:
            dict_return[row['Subcategory']] = row['Inclusion Setting']
    return dict_return


def _auditpol_export():
    try:
        dump = __salt__['cmd.run']('auditpol /get /category:* /r')
        if dump:
            dump = dump.split('\n')
            return dump
        else:
            log.error('Nothing was returned from the auditpol command.')
    except Exception:
        log.error('An error occurred running the auditpol command.')