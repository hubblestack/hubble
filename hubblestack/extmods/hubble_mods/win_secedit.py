# -*- encoding: utf-8 -*-
"""
Module for fetching security configuration values using secedit command

Audit Example 1:
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
Mandatory parameters:
    name - the name of the security configuration

Note: Comparison logic is moved to comparators. Module will just invoke the win_secedit command.
Comparator compatible with this module - dict, list

Sample Output:
1. dictionary with matchable value in 'sec_value'
    {'sec_value': ['24'], 'sec_name': 'PasswordHistorySize', 'coded_sec_value': '24'}
2. dictionary with matchable value in 'sec_value'
    {'sec_value': ['1', 'Adobe Systems'], 'sec_name': 'MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption', 'coded_sec_value': '1,"Adobe Systems"'}

Note: In normal execution, this module expects a security configuration name.
In case of chaining, it expects a string(security configuration name) from chaining
"""
import os
import logging
import salt.utils
import salt.utils.platform

try:
    import codecs
    import uuid

    HAS_WINDOWS_MODULES = True
except ImportError:
    HAS_WINDOWS_MODULES = False

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
        coded_sec_value = "No One"
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
    dump = "C:\ProgramData\{}.inf".format(uuid.uuid4())
    try:
        ret = __salt__['cmd.run']('secedit /export /cfg {0}'.format(dump))
        if ret:
            secedit_ret = _secedit_import(dump)
            ret = __salt__['file.remove'](dump)
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
        return ['defined (blank)']
    else:
        input_string = input_string.replace('"', '')
        input_string = input_string.split(',')
        return input_string


def _get_account_sid():
    """This helper function will get all the users and groups on the computer
    and return a dictionary"""
    win32 = __salt__['cmd.run']('Get-WmiObject win32_useraccount -Filter "localaccount=\'True\'"'
                                ' | Format-List -Property Name, SID', shell='powershell',
                                python_shell=True)
    win32 += '\n'
    win32 += __salt__['cmd.run']('Get-WmiObject win32_group -Filter "localaccount=\'True\'" | '
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
