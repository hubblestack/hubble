# -*- encoding: utf-8 -*-
'''

:maintainer: HubbleStack / madchills
:maturity: 2016.7.0
:platform: Windows
:requires: SaltStack

'''

from __future__ import absolute_import
import copy
import fnmatch
import logging
import salt.utils

try:
    import codecs
    import uuid
    HAS_WINDOWS_MODULES = True
except ImportError:
    HAS_WINDOWS_MODULES = False

log = logging.getLogger(__name__)
__virtualname__ = 'win_secedit'


def __virtual__():
    if not salt.utils.is_windows() or not HAS_WINDOWS_MODULES:
        return False, 'This audit module only runs on windows'
    return True


def audit(data_list, tags, debug=False, **kwargs):
    '''
    Runs secedit on the local machine and audits the return data
    with the CIS yaml processed by __virtual__
    '''
    __data__ = {}
    __secdata__ = _secedit_export()
    __sidaccounts__ = _get_account_sid()
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __tags__ = _get_tags(__data__)
    if debug:
        log.debug('secedit audit __data__:')
        log.debug(__data__)
        log.debug('secedit audit __tags__:')
        log.debug(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                name = tag_data['name']
                audit_type = tag_data['type']
                output = tag_data['match_output'].lower()

                # Blacklisted audit (do not include)
                if audit_type == 'blacklist':
                    if 'no one' in output:
                        if name not in __secdata__:
                            ret['Success'].append(tag_data)
                        else:
                            ret['Failure'].append(tag_data)
                    else:
                        if name in __secdata__:
                            secret = _translate_value_type(__secdata__[name], tag_data['value_type'], tag_data['match_output'])
                            if secret:
                                ret['Failure'].append(tag_data)
                            else:
                                ret['Success'].append(tag_data)

                # Whitelisted audit (must include)
                if audit_type == 'whitelist':
                    if name in __secdata__:
                        sec_value = __secdata__[name]
                        tag_data['found_value'] = sec_value
                        if 'MACHINE\\' in name:
                            match_output = _reg_value_translator(tag_data['match_output'])
                        else:
                            match_output = tag_data['match_output']
                        if ',' in sec_value and '\\' in sec_value:
                            sec_value = sec_value.split(',')
                            match_output = match_output.split(',')
                        if 'account' in tag_data['value_type']:
                            secret = _translate_value_type(sec_value, tag_data['value_type'], match_output, __sidaccounts__)
                        else:
                            secret = _translate_value_type(sec_value, tag_data['value_type'], match_output)
                        if secret:
                            ret['Success'].append(tag_data)
                        else:
                            ret['Failure'].append(tag_data)
                    else:
                        log.error('name {} was not in __secdata__'.format(name))
                        ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    '''
    Merge two yaml dicts together at the secedit:blacklist and
    secedit:whitelist level
    '''
    if __virtualname__ not in ret:
        ret[__virtualname__] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get(__virtualname__, {}):
            if topkey not in ret[__virtualname__]:
                ret[__virtualname__][topkey] = []
            for key, val in data[__virtualname__][topkey].iteritems():
                if profile and isinstance(val, dict):
                    val['nova_profile'] = profile
                ret[__virtualname__][topkey].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfullname')
    for toplist, toplevel in data.get(__virtualname__, {}).iteritems():
        # secedit:whitelist
        for audit_dict in toplevel:
            for audit_id, audit_data in audit_dict.iteritems():
                # secedit:whitelist:PasswordComplexity
                tags_dict = audit_data.get('data', {})
                # secedit:whitelist:PasswordComplexity:data
                tags = None
                for osfinger in tags_dict:
                    if osfinger == '*':
                        continue
                    osfinger_list = [finger.strip() for finger in osfinger.split(',')]
                    for osfinger_glob in osfinger_list:
                        if fnmatch.fnmatch(distro, osfinger_glob):
                            tags = tags_dict.get(osfinger)
                            break
                    if tags is not None:
                        break
                # If we didn't find a match, check for a '*'
                if tags is None:
                    tags = tags_dict.get('*', [])
                # secedit:whitelist:PasswordComplexity:data:Server 2012
                if isinstance(tags, dict):
                    # malformed yaml, convert to list of dicts
                    tmp = []
                    for name, tag in tags.iteritems():
                        tmp.append({name: tag})
                    tags = tmp
                for item in tags:
                    for name, tag in item.iteritems():
                        tag_data = {}
                        # Whitelist could have a dictionary, not a string
                        if isinstance(tag, dict):
                            tag_data = copy.deepcopy(tag)
                            tag = tag_data.pop('tag')
                        if tag not in ret:
                            ret[tag] = []
                        formatted_data = {'name': name,
                                          'tag': tag,
                                          'module': 'win_secedit',
                                          'type': toplist}
                        formatted_data.update(tag_data)
                        formatted_data.update(audit_data)
                        formatted_data.pop('data')
                        ret[tag].append(formatted_data)
    return ret


def _secedit_export():
    '''Helper function that will create(dump) a secedit inf file.  You can
    specify the location of the file and the file will persist, or let the
    function create it and the file will be deleted on completion.  Should
    only be called once.'''
    dump = "C:\ProgramData\{}.inf".format(uuid.uuid4())
    try:
        ret = __salt__['cmd.run']('secedit /export /cfg {0}'.format(dump))
        if ret:
            secedit_ret = _secedit_import(dump)
            ret = __salt__['file.remove'](dump)
            return secedit_ret
    except StandardError:
        log.debug('Error occurred while trying to get / export secedit data')
        return False, None


def _secedit_import(inf_file):
    '''This function takes the inf file that SecEdit dumps
    and returns a dictionary'''
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


def _get_account_sid():
    '''This helper function will get all the users and groups on the computer
    and return a dictionary'''
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
        lines = filter(None, lines)
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


def _translate_value_type(current, value, evaluator, __sidaccounts__=False):
    '''This will take a value type and convert it to what it needs to do.
    Under the covers you have conversion for more, less, and equal'''
    value = value.lower()
    if 'more' in value:
        if ',' in evaluator:
            evaluator = evaluator.split(',')[1]
        if ',' in current:
            current = current.split(',')[1]
        if '"' in current:
            current = current.replace('"', '')
        if '"' in evaluator:
            evaluator = evaluator.replace('"', '')
        if int(current) >= int(evaluator):
            return True
        else:
            return False
    elif 'less' in value:
        if ',' in evaluator:
            evaluator = evaluator.split(',')[1]
        if ',' in current:
            current = current.split(',')[1]
        if '"' in current:
            current = current.replace('"', '')
        if '"' in evaluator:
            evaluator = evaluator.replace('"', '')
        if int(current) <= int(evaluator):
            if current != '0':
                return True
            else:
                return False
        else:
            return False
    elif 'equal' in value:
        if ',' not in evaluator and type(evaluator) != list:
            tmp_evaluator = _evaluator_translator(evaluator)
            if tmp_evaluator != 'undefined':
                evaluator = tmp_evaluator
        if type(current) == list:
            ret_final = []
            for item in current:
                item = item.lower()
                if item in evaluator:
                    ret_final.append(True)
                else:
                    ret_final.append(False)
            if False in ret_final:
                return False
            else:
                return True
        if current.lower() == evaluator:
            return True
        else:
            return False
    elif 'contains' in value:
        if type(evaluator) != list:
            evaluator = evaluator.split(',')
            if type(current) != list:
                current = current.lower().split(',')
            ret_final = []
            for item in evaluator:
                if item in current:
                    ret_final.append(True)
                else:
                    ret_final.append(False)
            if False in ret_final:
                return False
            else:
                return True
    elif 'account' in value:
        evaluator = _account_audit(evaluator, __sidaccounts__)
        evaluator_list = evaluator.split(',')
        current_list = current.split(',')
        list_match = False
        for list_item in evaluator_list:
            if list_item in current_list:
                list_match = True
            else:
                list_match = False
                break
        if list_match:
            for list_item in current_list:
                if list_item in evaluator_list:
                    list_match = True
                else:
                    list_match = False
                    break
        else:
            return False
        if list_match:
            return True
        else:
            return False
    elif 'configured' in value:
        if current == '':
            return False
        elif current.lower().find(evaluator) != -1:
            return True
        else:
            return False
    else:
        return 'Undefined'


def _evaluator_translator(input_string):
    '''This helper function takes words from the CIS yaml and replaces
    them with what you actually find in the secedit dump'''
    if type(input_string) == str:
        input_string = input_string.replace(' ', '').lower()

    if 'enabled' in input_string:
        return '1'
    elif 'disabled' in input_string:
        return '0'
    elif 'success' in input_string:
        return '1'
    elif 'failure' in input_string:
        return '2'
    elif input_string == 'success,failure' or input_string == 'failure,success':
        return '3'
    elif input_string in ['0', '1', '2', '3']:
        return input_string
    else:
        log.debug('error translating evaluator from enabled/disabled or success/failure.'
                  '  Could have received incorrect string')
        return 'undefined'


def _account_audit(current, __sidaccounts__):
    '''This helper function takes the account names from the cis yaml and
    replaces them with the account SID that you find in the secedit dump'''
    user_list = current.split(', ')
    ret_string = ''
    if __sidaccounts__:
        for usr in user_list:
            if usr == 'Guest':
                if not ret_string:
                    ret_string = usr
                else:
                    ret_string += ',' + usr
            if usr in __sidaccounts__:
                if not ret_string:
                    ret_string = '*' + __sidaccounts__[usr]
                else:
                    ret_string += ',*' + __sidaccounts__[usr]
        return ret_string
    else:
        log.debug('getting the SIDs for each account failed')
        return False


def _reg_value_translator(input_string):
    input_string = input_string.lower()
    if input_string == 'enabled':
        return '4,1'
    elif input_string == 'disabled':
        return '4,0'
    elif input_string == 'users cant add or log on with microsoft accounts':
        return '4,3'
    elif input_string == 'administrators':
        return '1,"0"'
    elif input_string == 'lock workstation':
        return '1,"1"'
    elif input_string == 'accept if provided by client':
        return '4,1'
    elif input_string == 'classic - local users authenticate as themselves':
        return '4,1'
    elif input_string == 'rc4_hmac_md5, aes128_hmac_SHA1, aes256_hmac_sha1, future encryption types':
        return '4,2147483644'
    elif input_string == 'send ntlmv2 response only. Refuse lm & ntlm':
        return '4,5'
    elif input_string == 'negotiate signing':
        return '4,1'
    elif input_string == 'require ntlmv2 session security, require 128-bit encryption':
        return '4,537395200'
    elif input_string == 'prompt for consent on the secure desktop':
        return '4,2'
    elif input_string == 'automatically deny elevation requests':
        return '4,0'
    elif input_string == 'defined (blank)':
        return '7,'
    else:
        return input_string
