# -*- encoding: utf-8 -*-
"""
Module for fetching firewall data using firewall command

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
In normal execution, this module expects name and value_type
In case of chaining, it expects name and value_type from the chained parameter

Module Arguments
----------------
- name
    the name of the firewall setting
- value_type
    type of the firewall setting

Module Output
-------------
{'name': 'Enabled', 'value_type': 'domain', 'setting_value': 'true'}
Output: (True, <Above dict>)

Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
Since output is pretty dynamic. Following comparators can be used:
- dict

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)

Audit Example
---------------
check_unique_id:
  description: 'win_firewall check'
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
      module: win_firewall
      items:
        - args:
            name: 'Enabled'
            value_type: 'domain'
          comparator:
            type: "dict"
            match:
              setting_value:
                type: "string"
                match:
                  - 'True'

FDG Example:
------------
main:
  description: 'win_firewall fdg'
  module: win_firewall
  args:
    name: 'Enabled'
    value_type: 'domain'
"""
import os
import logging
import hubblestack.utils.platform

import hubblestack.module_runner.runner_utils as runner_utils
from hubblestack.exceptions import HubbleCheckValidationError
log = logging.getLogger(__name__)


def __virtual__():
    if not hubblestack.utils.platform.is_windows():
        return False, 'This audit module only runs on windows'
    return True


def execute(block_id, block_dict, extra_args=None):
    """
    Execute the module

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Chained argument dictionary, (If any)
        Example: {'chaining_args': {'result': {"name": "LogFileName", "value_type": "public"}, 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing win_firewall module for id: {0}'.format(block_id))
    __firewalldata__ = _import_firewall()
    if not __firewalldata__:
        return runner_utils.prepare_negative_result_for_module(block_id, "firewall data couldn't be fetched")

    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        name = chained_result.get('name')
        value_type = chained_result.get('value_type')
    else:
        name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
        value_type = runner_utils.get_param_for_module(block_id, block_dict, 'value_type')

    try:
        setting_value = __firewalldata__.get(value_type).get(name).lower()
    except Exception as e:
        log.debug("for block id %s, setting name %s and value type %s is not "
                  "found in firewall data", block_id, name, value_type)
        setting_value = "Not Found"
    result = {"name": name, "value_type": value_type, "setting_value": setting_value}
    log.debug("win_firewall module output for block_id %s, is %s", block_id, result)

    if not result:
        return runner_utils.prepare_negative_result_for_module(block_id, "firewall setting couldn't be fetched")

    return runner_utils.prepare_positive_result_for_module(block_id, result)


def validate_params(block_id, block_dict, extra_args=None):
    """
        Validate all mandatory params required for this module

        :param block_id:
            id of the block
        :param block_dict:
            parameter for this module
        :param extra_args:
            Chained argument dictionary, (If any)
            Example: {'chaining_args': {'result': {"name": "LogFileName", "value_type": "public"}, 'status': True},
                  'caller': 'Audit'}

        Raises:
            AuditCheckValidationError: For any validation error
        """
    log.debug('Module: win_firewall. Start validating params for check-id: {0}'.format(block_id))

    error = {}

    # fetch required param
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        name = chained_result.get('name')
        value_type = chained_result.get('value_type')
    else:
        name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
        value_type = runner_utils.get_param_for_module(block_id, block_dict, 'value_type')

    if not name:
        error['name'] = 'Mandatory parameter: name not found for id: %s' % block_id
    if not value_type:
        error['value_type'] = 'Mandatory parameter: value_type not found for id: %s' % block_id

    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    """
    For getting params to log, in non-verbose logging

    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Chained argument dictionary, (If any)
        Example: {'chaining_args': {'result': {"name": "LogFileName", "value_type": "public"}, 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for win_firewall and id: {0}'.format(block_id))

    # fetch required param
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        name = chained_result.get('name')
        value_type = chained_result.get('value_type')
    else:
        name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
        value_type = runner_utils.get_param_for_module(block_id, block_dict, 'value_type')

    return {'name': name, 'value_type': value_type}


def _export_firewall():
    dump = []
    try:
        temp = __mods__['cmd.run']('mode con:cols=1000 lines=1000; Get-NetFirewallProfile -PolicyStore ActiveStore', shell='powershell', python_shell=True)
        temp = temp.split('\r\n\r\n')
        if temp:
            for item in temp:
                if item != '':
                    dump.append(item)
            return dump
        else:
            log.error('Nothing was returned from the firewall command.')
    except Exception:
        log.error('An error occurred running the firewall command.')


def _import_firewall():
    dict_return = {}
    export = _export_firewall()
    for line in export:
        temp_values = {}
        values = line.split('\n')
        for value in values:
            if value:
                value_list = value.split(':')
                if len(value_list) < 2:
                    continue
                temp_values[value_list[0].strip()] = value_list[1].strip()
        dict_return[temp_values['Name']] = temp_values
    return dict_return


def get_failure_reason(block_id, block_dict, extra_args=None):
    """
    The function is used to find the action that was performed during the audit check
    :param block_id:
        id of the block
    :param block_dict:
        parameter for this module
    :param extra_args:
        Extra argument dictionary, (If any)
        Example: {'chaining_args': {'result': {"name": "LogFileName", "value_type": "public"}, 'status': True},
                  'caller': 'Audit'}
    :return:
    """
    name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    return "Fetching firewall rule {0}".format(name)
