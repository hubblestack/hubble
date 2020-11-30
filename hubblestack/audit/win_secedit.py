# -*- encoding: utf-8 -*-
"""
Module for fetching security configuration values using secedit command

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
In normal execution, this module expects security configuration name
In case of chaining, it expects security configuration name from the chained parameter

Module Arguments
----------------
- name
    the name of the security configuration

Module Output
-------------
Sample Output:
1. dictionary with matchable value in 'sec_value'
    {'sec_value': ['24'], 'sec_name': 'PasswordHistorySize', 'coded_sec_value': '24'}
2. dictionary with matchable value in 'sec_value'
    {'sec_value': ['1', 'Adobe Systems'], 'sec_name': 'MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption', 'coded_sec_value': '1,"Adobe Systems"'}

Output: (True, <above dict>)

Note: Module returns a tuple
    First value being the status of module
    Second value is the actual output from module

Compatible Comparators
----------------------
- list

For detailed documentation on comparators,
read comparator's implementations at (/hubblestack/extmods/comparators/)

Audit Example 1:
---------------
check_unique_id:
  description: 'win_secedit check'
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
      module: win_secedit
      items:
        - args:
            name: 'NewAdministratorName'
            value_type: 'equal'
          comparator:
            type: "dict"
            match:
              sec_value:
                type: "list"
                match:
                  - '"Administrator"'

Audit Example 2:
---------------
check_unique_id:
  description: 'win_secedit check'
  tag: 'ADOBE-01'
  implementations:
    - filter:
        grains: 'G@osfinger:Microsoft Windows Server 2016*'
      hubble_version: '>3 AND <7 AND <8'
      module: win_secedit
      items:
        - args:
            name: 'SeRemoteInteractiveLogonRight'
            value_type: 'account'
          comparator:
            type: "dict"
            match:
              sec_value:
                type: "list"
                match_all:
                  - "Administrators"
                  - "Remote Desktop Users"

FDG Example:
------------
main:
  description: 'win_secedit fdg'
  module: win_secedit
  args:
    name: SeRemoteInteractiveLogonRight
"""
import os
import logging
import hubblestack.utils
import hubblestack.utils.platform

try:
    import codecs
    import uuid

    HAS_WINDOWS_MODULES = True
except ImportError:
    HAS_WINDOWS_MODULES = False

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
        Example: {'chaining_args': {'result': "SeRemoteInteractiveLogonRight", 'status': True},
                  'caller': 'Audit'}

    returns:
        tuple of result(value) and status(boolean)
    """
    log.debug('Executing win_secedit module for id: {0}'.format(block_id))
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        sec_name = chained_result
    else:
        sec_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')

    try:
        value_type = runner_utils.get_param_for_module(block_id, block_dict, 'value_type')
    except Exception as e:
        log.debug("optional param, 'value_type' not provided as input, taking '' as value type")
        value_type = ''

    __secdata__ = _secedit_export()
    coded_sec_value = __secdata__.get(sec_name)

    if coded_sec_value is None:
        result = {'sec_name': sec_name, 'coded_sec_value': "No One", 'sec_value': ['']}
        log.debug("win_secedit module output for block_id %s, is %s", block_id, result)
        return runner_utils.prepare_positive_result_for_module(block_id, result)
    if 'account' == value_type:
        sec_value = _get_account_name(coded_sec_value)
    elif 'MACHINE\\' in sec_name:
        sec_value = _reg_value_reverse_translator(coded_sec_value)
    else:
        if ',' in coded_sec_value:
            sec_value = coded_sec_value.split(',')
        else:
            sec_value = [coded_sec_value]

    if not sec_value:
        return runner_utils.prepare_negative_result_for_module(block_id, "security config value couldn't be fetched")

    result = {'sec_name': sec_name, 'coded_sec_value': coded_sec_value, 'sec_value': sec_value}
    log.debug("win_secedit module output for block_id %s, is %s", block_id, result)

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
            Example: {'chaining_args': {'result': "SeRemoteInteractiveLogonRight", 'status': True},
                  'caller': 'Audit'}

        Raises:
            HubbleCheckValidationError: For any validation error
        """
    log.debug('Module: win_secedit. Start validating params for check-id: {0}'.format(block_id))

    error = {}

    # fetch required param
    chained_pkg_name = None
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        chained_pkg_name = chained_result
    else:
        sec_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')
    if not chained_pkg_name and not sec_name:
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
        Example: {'chaining_args': {'result': "SeRemoteInteractiveLogonRight", 'status': True},
                  'caller': 'Audit'}
    """
    log.debug('get_filtered_params_to_log for win_secedit and id: {0}'.format(block_id))

    # fetch required param
    chained_result = runner_utils.get_chained_param(extra_args)
    if chained_result:
        sec_name = chained_result
    else:
        sec_name = runner_utils.get_param_for_module(block_id, block_dict, 'name')

    return {'name': sec_name}


def _secedit_export():
    """Helper function that will create(dump) a secedit inf file.  You can
    specify the location of the file and the file will persist, or let the
    function create it and the file will be deleted on completion.  Should
    only be called once."""
    dump = r"C:\ProgramData\{}.inf".format(uuid.uuid4())
    try:
        ret = __mods__['cmd.run']('secedit /export /cfg {0}'.format(dump))
        if ret:
            secedit_ret = _secedit_import(dump)
            ret = __mods__['file.remove'](dump)
            return secedit_ret
    except Exception as e:
        log.debug('Error occurred while trying to get / export secedit data. Error - %s', e)
        return False, None


def _secedit_import(inf_file):
    """This function takes the inf file that SecEdit dumps
    and returns a dictionary"""
    sec_return = {}
    with codecs.open(inf_file, 'r', encoding='utf-16') as f:
        for line in f:
            line = str(line).replace('\r\n', '')
            if not line.startswith('[') and not line.startswith('Unicode'):
                if line.find(' = ') != -1:
                    k, v = line.split(' = ')
                    sec_return[k] = v
                else:
                    k, v = line.split('=')
                    sec_return[k] = v
    return sec_return


def _reg_value_reverse_translator(input_string):
    """
    This function will translate the actual values found in security config to the values found in CIS benchmark documents.
    Eg. '1,"1"' is a configuration found in security configurations on a windows system. And 'lock workstation' is the
    corresponding value in the CIS Benchmark.
    """
    if input_string == '4,1':
        return ['Enabled', 'accept if provided by client', 'classic - local users authenticate as themselves',
                'negotiate signing']
    elif input_string == '4,0':
        return ['disabled', 'automatically deny elevation requests']
    elif input_string == '4,3':
        return ['users cant add or log on with microsoft accounts']
    elif input_string == '1,"0"':
        return ['administrators']
    elif input_string == '1,"1"':
        return ['lock workstation']
    elif input_string == '4,2147483644':
        return ['rc4_hmac_md5, aes128_hmac_sha1, aes256_hmac_sha1, future encryption types']
    elif input_string == '4,5':
        return ['send ntlmv2 response only. refuse lm & ntlm']
    elif input_string == '4,537395200':
        return ['require ntlmv2 session security, require 128-bit encryption']
    elif input_string == '4,2':
        return ['prompt for consent on the secure desktop']
    elif input_string == '7,':
        return ['']
    else:
        input_string = input_string.replace('"', '')
        input_string = input_string.split(',')
        return input_string


def _get_account_sid():
    """This helper function will get all the users and groups on the computer
    and return a dictionary"""
    win32 = __mods__['cmd.run']('Get-WmiObject win32_useraccount -Filter "localaccount=\'True\'"'
                                ' | Format-List -Property Name, SID', shell='powershell',
                                python_shell=True)
    win32 += '\n'
    win32 += __mods__['cmd.run']('Get-WmiObject win32_group -Filter "localaccount=\'True\'" | '
                                 'Format-List -Property Name, SID', shell='powershell',
                                 python_shell=True)
    if win32:

        dict_return = {}
        lines = win32.split('\n')
        lines = [_f for _f in lines if _f]
        if 'local:' in lines:
            lines.remove('local:')
        for line in lines:
            line = line.strip()
            if line != '' and ' : ' in line:
                k, v = line.split(' : ')
                if k.lower() == 'name':
                    key = v
                else:
                    dict_return[key] = v
        if dict_return:
            if 'LOCAL SERVICE' not in dict_return:
                dict_return['LOCAL SERVICE'] = 'S-1-5-19'
            if 'NETWORK SERVICE' not in dict_return:
                dict_return['NETWORK SERVICE'] = 'S-1-5-20'
            if 'SERVICE' not in dict_return:
                dict_return['SERVICE'] = 'S-1-5-6'
            return dict_return
        else:
            log.debug('Error parsing the data returned from powershell')
            return False
    else:
        log.debug('error occurred while trying to run powershell '
                  'get-wmiobject command')
        return False


def _get_account_name(account_id):
    """
    Return the account name if we have the account ID
    """
    ret_list = []
    __sidaccounts__ = _get_account_sid()
    account_ids = account_id.split(',')
    for sec_value in account_ids:
        for key, value in __sidaccounts__.items():
            if sec_value[1:].lower() == value.lower():
                ret_list.append(key)
    return ret_list
