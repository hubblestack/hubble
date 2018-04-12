# -*- encoding: utf-8 -*-
'''

:maintainer: HubbleStack / madchills
:maturity: 2016.7.0
:platform: Windows
:requires: SaltStack

'''

from __future__ import absolute_import
import copy
import csv
import fnmatch
import logging
import salt.utils
import salt.utils.platform


log = logging.getLogger(__name__)
__virtualname__ = 'win_auditpol'


def __virtual__():
    if not salt.utils.platform.is_windows():
        return False, 'This audit module only runs on windows'
    return True

def apply_labels(__data__, labels):
    '''
    Filters out the tests whose label doesn't match the labels given when running audit and returns a new data structure with only labelled tests.
    '''
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
    '''
    Runs auditpol on the local machine and audits the return data
    with the CIS yaml processed by __virtual__
    '''
    __data__ = {}
    __auditdata__ = _auditpol_import()
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __data__ = apply_labels(__data__, labels)
    __tags__ = _get_tags(__data__)
    if debug:
        log.debug('auditpol audit __data__:')
        log.debug(__data__)
        log.debug('auditpol audit __tags__:')
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
                match_output = tag_data['match_output'].lower()

                # Blacklisted audit (do not include)
                if 'blacklist' in audit_type:
                    if name not in __auditdata__:
                        ret['Success'].append(tag_data)
                    else:
                        tag_data['failure_reason'] = "Value of balcklisted attribute '{0}' is " \
                                                     "configured on your system. It should not " \
                                                     "be configured".format(name)
                        ret['Failure'].append(tag_data)

                # Whitelisted audit (must include)
                if 'whitelist' in audit_type:
                    if name in __auditdata__:
                        audit_value = __auditdata__[name].lower()
                        tag_data['found_value'] = audit_value
                        secret = _translate_value_type(audit_value, tag_data['value_type'], match_output)
                        if secret:
                            ret['Success'].append(tag_data)
                        else:
                            tag_data['failure_reason'] = "Value of attribute '{0}' is currently" \
                                                         " set as '{1}'. Expected value is '{2}({3})'" \
                                                         .format(name,
                                                                 audit_value,
                                                                 match_output,
                                                                 tag_data['value_type'])
                            ret['Failure'].append(tag_data)
                    else:
                        log.debug('When trying to audit the advanced auditpol section,'
                                  ' the yaml contained incorrect data for the key')

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
                # secedit:whitelist:PasswordComplexity:data:Windows 2012
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
                                          'module': 'win_auditpol',
                                          'type': toplist}
                        formatted_data.update(tag_data)
                        formatted_data.update(audit_data)
                        formatted_data.pop('data')
                        ret[tag].append(formatted_data)
    return ret


def _auditpol_export():
    try:
        dump = __salt__['cmd.run']('auditpol /get /category:* /r')
        if dump:
            dump = dump.split('\n')
            return dump
        else:
            log.error('Nothing was returned from the auditpol command.')
    except StandardError:
        log.error('An error occurred running the auditpol command.')


def _auditpol_import():
    dict_return = {}
    export = _auditpol_export()
    auditpol_csv = csv.DictReader(export)
    for row in auditpol_csv:
        if row:
            dict_return[row['Subcategory']] = row['Inclusion Setting']
    return dict_return


def _translate_value_type(current, value, evaluator):
    if 'equal' in value:
        if current == evaluator:
            return True
        else:
            return False
