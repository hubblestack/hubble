# -*- encoding: utf-8 -*-
"""
Module for fetching firewall data using firewall command

Audit Example 1:
---------------
check_unique_id:
  description: 'win_firewall check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:Microsoft Windows Server 2016*'
      hubble_version: '>3 AND <7 AND <8'
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
Mandatory parameters:
    name - the name of the firewall setting
    value_type: type of the firewall setting

Note: Comparison logic is moved to comparators. Module will just invoke the firewall command.
Comparator compatible with this module - dict, string

Sample Output:
1. dictionary with matchable value in 'setting_value'
    {'name': 'Enabled', 'value_type': 'domain', 'setting_value': 'true'}

Note: In normal execution, this module expects a firewall setting name and type.
In case of chaining, it expects two args string(firewall setting name) from chaining
"""
import os
import logging
import salt.utils
import salt.utils.platform

import hubblestack.extmods.module_runner.runner_utils as runner_utils
from hubblestack.utils.hubble_error import HubbleCheckValidationError
log = logging.getLogger(__name__)


def __virtual__():
    if not salt.utils.platform.is_windows():
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
        temp = __salt__['cmd.run']('mode con:cols=1000 lines=1000; Get-NetFirewallProfile -PolicyStore ActiveStore', shell='powershell', python_shell=True)
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
