# -*- encoding: utf-8 -*-
r"""
Module for fetching registry values from windows registry

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
In normal execution, this module expects a registry name
In case of chaining, it expects registry name from the chained parameter

Module Arguments
----------------
- name
    registry name

Module Output
-------------
Sample Output:
1. can be dictionary with value being an int like
    {"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention": 0}
2. can be a dictionary with value being a str like
    {"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\\*\NETLOGON":
                                'RequireMutualAuthentication=1,RequireIntegrity=1'}

Output: (True, <above dictionary>)

Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
- dict
- number

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)


Audit Example 1:
---------------
check_unique_id:
  description: 'win_reg check'
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
"""

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
    r"""
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
    result = {reg_name: secret}
    log.debug("win_reg module output for block_id %s, is %s", block_id, result)

    if secret is False:
        return runner_utils.prepare_negative_result_for_module(block_id,
                                                               "registry value couldn't "
                                                               "be fetched for reg_name {0}".format(reg_name))

    return runner_utils.prepare_positive_result_for_module(block_id, result)


def validate_params(block_id, block_dict, extra_args=None):
    r"""
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
    else:
        reg_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    if not chained_pkg_name and not reg_name:
        error['name'] = 'Mandatory parameter: name not found for id: %s' % block_id
    if error:
        raise HubbleCheckValidationError(error)

    log.debug('Validation success for check-id: {0}'.format(block_id))


def get_filtered_params_to_log(block_id, block_dict, extra_args=None):
    r"""
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
        sid_return = __mods__['cmd.run']('reg query hku').split('\n')
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
    reg_result = __mods__['reg.read_value'](reg_hive, reg_key, reg_value)
    if reg_result.get('success'):
        if reg_result.get('vdata') == '(value not set)':
            return False
        else:
            return reg_result.get('vdata')
    else:
        return False
