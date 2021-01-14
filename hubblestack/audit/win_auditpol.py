# -*- encoding: utf-8 -*-
"""
Module for fetching audit policies values using auditpol command

Note: Now each module just returns its output (As Data gathering)
      For Audit checks, comparison logic is now moved to comparators. 
      See below sections for more understanding

Usable in Modules
-----------------
- Audit
- FDG

Common Schema
-------------
- check_unique_id
    Its a unique string within a yaml file.
    It is present on top of a yaml block

- description 
    Description of the check

- tag 
    (Applicable only for Audit)
    Check tag value

- sub_check (Optional, default: false) 
    (Applicable only for Audit)
    If true, its individual result will not be counted in compliance
    It might be referred in some boolean expression

- failure_reason (Optional) 
    (Applicable only for Audit)
    By default, module will generate failure reason string at runtime
    If this is passed, this will override module's actual failure reason

- invert_result (Optional, default: false) 
    (Applicable only for Audit)
    This is used to flip the boolean output from a check

- implementations
    (Applicable only for Audit)
    Its an array of implementations, usually for multiple operating systems.
    You can specify multiple implementations here for respective operating system.
    Either one or none will be executed.

- grains (under filter)
    (Applicable only for Audit)
    Any grains with and/or/not supported. This is used to filter whether 
    this check can run on the current OS or not.
    To run this check on all OS, put a '*'

    Example:
    G@docker_details:installed:True and G@docker_details:running:True and not G@osfinger:*Flatcar* and not G@osfinger:*CoreOS*

- hubble_version (Optional)
    (Applicable only for Audit)
    It acts as a second level filter where you can specify for which Hubble version,
    this check is compatible with. You can specify a boolean expression as well

    Example:
    '>3.0 AND <5.0'

- module
    The name of Hubble module.

- return_no_exec (Optional, Default: false)
    (Applicable only for Audit)
    It takes a boolean (true/false) value.
    If its true, the implementation will not be executed. And true is returned
    
    This can be useful in cases where you don't have any implementation for some OS,
    and you want a result from the block. Else, your meta-check(bexpr) will be failed.

- items
    (Applicable only for Audit)
    An array of multiple module implementations. At least one block is necessary.
    Each item in array will result into a boolean value.
    If multiple module implementations exists, final result will be evaluated as 
    boolean AND (default, see parameter: check_eval_logic)

- check_eval_logic (Optional, default: and)
    (Applicable only for Audit)
    If there are multiple module implementations in "items" (above parameter), this parameter
    helps in evaluating their result. Default value is "and"
    It accepts only values: and/or

- args
    Arguments specific to a module.

- comparator
    For the purpose of comparing output of module with expected values.
    Parameters depends upon the comparator used.
    For detailed documentation on comparators, 
    read comparator's implementations at (/hubblestack/extmods/comparators/)

FDG Schema
----------
FDG schema is kept simple. Only following keywords allowed:
- Unique id
    Unique string id
- description (Optional)
    Some description
- module
    Name of the module
- args
    Module arguments
- comparator (Only in case of Audit-FDG connector)

FDG Chaining
------------
In normal execution, this module expects audit policy name. 
In case of chaining, it expects audit policy name from the chained parameter

Module Arguments
----------------
- name
    the name of the audit policy

Module Output
-------------
{'Distribution Group Management': 'Success and Failure'}

Output: (True, <Above output>)

Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
- dict

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)


Audit Example
---------------
check_unique_id:
  description: 'win_auditpol check'
  tag: 'ADOBE-01'
  sub_check: false (Optional, default: false)
  failure_reason: 'a sample failure reason' (Optional)
  invert_result: false (Optional, default: false)
  implementations:
    - filter:
        grains: 'G@osfinger:CentOS*Linux-7'
      hubble_version: '>3 AND <7 AND <8'
      # return_no_exec: true (Optional, default: false)
      check_eval_logic: and (Optional, default: and)
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
"""

import csv
import logging
import hubblestack.utils.platform

import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.exceptions import HubbleCheckValidationError

log = logging.getLogger(__name__)


def __virtual__():
    if not hubblestack.utils.platform.is_windows():
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
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        name = chained_result.get('name')
    else:
        name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    # fetch required param
    if not name:
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
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        name = chained_result.get('name')
    else:
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
        dump = __mods__['cmd.run']('auditpol /get /category:* /r')
        if dump:
            dump = dump.split('\n')
            return dump
        else:
            log.error('Nothing was returned from the auditpol command.')
    except Exception:
        log.error('An error occurred running the auditpol command.')
