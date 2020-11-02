# -*- encoding: utf-8 -*-
r"""
Module for fetching registry values from windows registry

Audit Example 1:
---------------
check_unique_id:
  description: 'win_reg check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:Microsoft Windows Server 2016*'
      hubble_version: '>3 AND <7 AND <8'
      module: win_reg
      items:
        - args:
            name: 'HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
          comparator:
            type: "dict"
            match:
              HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention:
                 type: "number"
                 match: "== 0"

Audit Example 2:
---------------
check_unique_id:
  description: 'win_reg check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:Microsoft Windows Server 2016*'
      hubble_version: '>3 AND <7 AND <8'
      module: win_reg
      items:
        - args:
            name: 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays'
          comparator:
            type: "dict"
            match:
              HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd\PasswordAgeDays:
                 type: "number"
                 match: "<= 30"

FDG Example:
------------
main:
  description: 'win_reg fdg'
  module: win_reg
  args:
    name: HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPreventions
Mandatory parameters:
    name - registry name

Note: Comparison logic is moved to comparators. Module will just invoke the win_reg command.
Comparator compatible with this module - number, string

Sample Output:
1. can be dictionary with value being an int like
    {"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention": 0}
2. can be a dictionary with value being a str like
    {"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\NETLOGON":
                                'RequireMutualAuthentication=1,RequireIntegrity=1'}

Note: In normal execution, this module expects a registry name.
In case of chaining, it expects a string(registry name) from chaining
"""

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
        Example: {'chaining_args': {'result': "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize", 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing win_reg module for id: {0}'.format(block_id))

    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        reg_name = chained_result
    else:
        reg_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    reg_dict = _reg_path_splitter(reg_name)
    secret = _find_option_value_in_reg(reg_dict.get('hive'), reg_dict.get('key'), reg_dict.get('value'))
    if isinstance(secret, dict):
        return runner_utils.prepare_negative_result_for_module(block_id,
                                                               "registry output is a dict, currently unsupported")
    result = {reg_name: secret}
    log.debug("win_reg module output for block_id %s, is %s", block_id, result)

    if secret is False:
        return runner_utils.prepare_negative_result_for_module(block_id, "registry value couldn't be fetched")

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
            Example: {'chaining_args': {'result': "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize", 'status': True},
            'caller': 'Audit'}

        Raises:
            HubbleCheckValidationError: For any validation error
        """
    log.debug('Module: win_reg. Start validating params for check-id: {0}'.format(block_id))

    error = {}

    # fetch required param
    chained_pkg_name = None
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        chained_pkg_name = chained_result
    reg_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    if not chained_pkg_name and not reg_name:
        error['name'] = 'Mandatory parameter: name not found for id: %s' % block_id
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
        Example: {'chaining_args': {'result': "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize", 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for win_reg and id: {0}'.format(block_id))

    # fetch required param
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        reg_name = chained_result
    else:
        reg_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')

    return {'name': reg_name}


def _reg_path_splitter(reg_path):
    dict_return = {}
    dict_return['hive'], temp = reg_path.split('\\', 1)
    if '\\\\*\\' in temp:
        dict_return['key'], dict_return['value'] = temp.rsplit('\\\\', 1)
        dict_return['value'] = '\\\\{}'.format(dict_return['value'])
    else:
        dict_return['key'], dict_return['value'] = temp.rsplit('\\', 1)

    return dict_return


def _find_option_value_in_reg(reg_hive, reg_key, reg_value):
    """
    helper function to retrieve Windows registry settings for a particular
    option
    """
    if reg_hive.lower() in ('hku', 'hkey_users'):
        key_list = []
        ret_dict = {}
        sid_return = __salt__['cmd.run']('reg query hku').split('\n')
        for line in sid_return:
            if '\\' in line:
                key_list.append(line.split('\\')[1].strip())
        for sid in key_list:
            if len(sid) <= 15 or '_Classes' in sid:
                continue
            temp_reg_key = reg_key.replace('<SID>', sid)
            ret_dict[sid] = _read_reg_value(reg_hive, temp_reg_key, reg_value)
        return ret_dict
    else:
        return _read_reg_value(reg_hive, reg_key, reg_value)


def _read_reg_value(reg_hive, reg_key, reg_value):
    reg_result = __salt__['reg.read_value'](reg_hive, reg_key, reg_value)
    if reg_result.get('success'):
        if reg_result.get('vdata') == '(value not set)':
            return False
        else:
            return reg_result.get('vdata')
    else:
        return False
