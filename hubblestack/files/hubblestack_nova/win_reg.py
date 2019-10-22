# -*- encoding: utf-8 -*-
"""
"""


import copy
import fnmatch
import logging
import salt.utils
import salt.utils.platform


log = logging.getLogger(__name__)
__virtualname__ = 'win_reg'


def __virtual__():
    if not salt.utils.platform.is_windows():
        return False, 'This audit module only runs on windows'
    return True

def apply_labels(__data__, labels):
    """
    Filters out the tests whose label doesn't match the labels given when running audit and returns a new data structure with only labelled tests.
    """
    labelled_data = {}
    if labels:
        labelled_data[__virtualname__] = {}
        for topkey in ('blacklist', 'whitelist'):
            if topkey in __data__.get(__virtualname__, {}):
                labelled_test_cases=[]
                for test_case in __data__[__virtualname__].get(topkey, []):
                    # each test case is a dictionary with just one key-val pair. key=test name, val=test data, description etc
                    if isinstance(test_case, dict) and test_case:
                        test_case_body = test_case.get(next(iter(test_case)))
                        if set(labels).issubset(set(test_case_body.get('labels',[]))):
                            labelled_test_cases.append(test_case)
                labelled_data[__virtualname__][topkey]=labelled_test_cases
    else:
        labelled_data = __data__
    return labelled_data

def audit(data_list, tags, labels, debug=False, **kwargs):
    """
    Runs salt reg query on the local machine and audits the return data
    with the CIS yaml processed by __virtual__
    """
    __data__ = {}
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __data__ = apply_labels(__data__, labels)
    __tags__ = _get_tags(__data__)
    __is_domain_controller__ = _is_domain_controller()
    if debug:
        log.debug('registry audit __data__:')
        log.debug(__data__)
        log.debug('registry audit __tags__:')
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
                try:
                    match_output = int(tag_data['match_output'])
                except ValueError:
                    match_output = tag_data['match_output'].lower()

                run_on_dc = tag_data.get('run_on_dc', True)
                run_on_member_server = tag_data.get('run_on_member_server', True)
                if __is_domain_controller__ and not run_on_dc:
                    continue
                if not __is_domain_controller__ and not run_on_member_server:
                    continue

                reg_dict = _reg_path_splitter(name)

                # Blacklisted audit (do not include)
                if 'blacklist' in audit_type:
                    secret = _find_option_value_in_reg(reg_dict['hive'], reg_dict['key'], reg_dict['value'])
                    if secret:
                        tag_data['failure_reason'] = "Value of blacklisted registry key '{0}:{1}:{2}' " \
                                                     "is set to value '{3}'. It should not be configured." \
                                                     .format(reg_dict['hive'],
                                                             reg_dict['key'],
                                                             reg_dict['value'],
                                                             secret)
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)

                # Whitelisted audit (must include)
                if 'whitelist' in audit_type:
                    current = _find_option_value_in_reg(reg_dict['hive'], reg_dict['key'], reg_dict['value'])
                    if isinstance(current, dict):
                        tag_data['value_found'] = current
                        if any(x is False for x in current.values()):
                            ret['Failure'].append(tag_data)
                        else:
                            answer_list = []
                            for item in current:
                                answer_list.append(_translate_value_type(current[item], tag_data['value_type'], match_output))

                            if False in answer_list:
                                tag_data['failure_reason'] = "Value of registry key '{0}:{1}:{2}' should" \
                                                             " be set to '{4}({5})'. It is set to some other" \
                                                             " value for one or more SID(s)". \
                                                             format(reg_dict['hive'],
                                                                    reg_dict['key'],
                                                                    reg_dict['value'],
                                                                    current,
                                                                    match_output,
                                                                    tag_data['value_type'])
                                ret['Failure'].append(tag_data)
                            else:
                                ret['Success'].append(tag_data)
                    else:
                        if current is not False:
                            secret = _translate_value_type(current, tag_data['value_type'], match_output)
                            if secret:
                                tag_data['value_found'] = current
                                ret['Success'].append(tag_data)
                            else:
                                tag_data['failure_reason'] = "Value of registry key '{0}:{1}:{2}' is set to " \
                                                             "value '{3}'. It should be set to '{4}({5})'." \
                                                             .format(reg_dict['hive'],
                                                                     reg_dict['key'],
                                                                     reg_dict['value'],
                                                                     current,
                                                                     match_output,
                                                                     tag_data['value_type'])
                                tag_data['value_found'] = current
                                ret['Failure'].append(tag_data)

                        else:
                            tag_data['value_found'] = None
                            tag_data['failure_reason'] = "Value of registry key '{0}:{1}:{2}' could not be " \
                                                         "found. It should be set to '{3}({4})'." \
                                                         .format(reg_dict['hive'],
                                                                 reg_dict['key'],
                                                                 reg_dict['value'],
                                                                 match_output,
                                                                 tag_data['value_type'])
                            ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    """
    Merge two yaml dicts together at the secedit:blacklist and
    secedit:whitelist level
    """
    if __virtualname__ not in ret:
        ret[__virtualname__] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get(__virtualname__, {}):
            if topkey not in ret[__virtualname__]:
                ret[__virtualname__][topkey] = []
            for key, val in data[__virtualname__][topkey].items():
                if profile and isinstance(val, dict):
                    val['nova_profile'] = profile
                ret[__virtualname__][topkey].append({key: val})
    return ret


def _get_tags(data):
    """
    Retrieve all the tags for this distro from the yaml
    """
    ret = {}
    distro = __grains__.get('osfullname')
    for toplist, toplevel in data.get(__virtualname__, {}).items():
        # secedit:whitelist
        for audit_dict in toplevel:
            for audit_id, audit_data in audit_dict.items():
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
                # secedit:whitelist:PasswordComplexity:data:Windows 2012
                if isinstance(tags, dict):
                    # malformed yaml, convert to list of dicts
                    tmp = []
                    for name, tag in tags.items():
                        tmp.append({name: tag})
                    tags = tmp
                for item in tags:
                    for name, tag in item.items():
                        tag_data = {}
                        # Whitelist could have a dictionary, not a string
                        if isinstance(tag, dict):
                            tag_data = copy.deepcopy(tag)
                            tag = tag_data.pop('tag')
                        if tag not in ret:
                            ret[tag] = []
                        formatted_data = {'name': name,
                                          'tag': tag,
                                          'module': 'win_reg',
                                          'type': toplist}
                        formatted_data.update(tag_data)
                        formatted_data.update(audit_data)
                        formatted_data.pop('data')
                        ret[tag].append(formatted_data)
    return ret


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
            reg_result = __salt__['reg.read_value'](reg_hive, temp_reg_key, reg_value)
            if reg_result['success']:
                if reg_result['vdata'] == '(value not set)':
                    ret_dict[sid] = False
                else:
                    ret_dict[sid] = reg_result['vdata']
            else:
                ret_dict[sid] = False
        return ret_dict

    else:
        reg_result = __salt__['reg.read_value'](reg_hive, reg_key, reg_value)
        if reg_result['success']:
            if reg_result['vdata'] == '(value not set)':
                return False
            else:
                return reg_result['vdata']
        else:
            return False


def _translate_value_type(current, value, evaluator):
    try:
        current = int(current)
    except ValueError:
        log.debug('registry value is a string')
        current = current.lower()
    if 'equal' in value:
        if current == evaluator:
            return True
        else:
            return False
    if 'domain' in value:
        pass
    if 'more' in value:
        if current >= evaluator:
            return True
        else:
            return False
    if 'less' in value:
        if current <= evaluator and current != 0:
            return True
        else:
            return False
    if 'user' in value:
        log.debug("HKEY_Users is still a work in progress")
        return True


def _is_domain_controller():
    ret = __salt__['reg.read_value'](hive="HKLM",
                                     key=r"SYSTEM\CurrentControlSet\Control\ProductOptions",
                                     vname="ProductType")
    if ret['vdata'] == "LanmanNT":
        return True
    else:
        return False
