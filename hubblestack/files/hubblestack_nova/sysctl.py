# -*- encoding: utf-8 -*-
'''
HubbleStack Nova module for using sysctl to verify sysctl parameter.

:maintainer: HubbleStack / avb76
:maturity: 2016.7.0
:platform: Linux
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'sysctl' key, it will
use that data.

Sample YAML data, with inline comments:

sysctl:
  randomize_va_space:  # unique ID
    data:
      'CentOS-6':  #osfinger grain
        - 'kernel.randomize_va_space':  #sysctl param to check
            tag: 'CIS-1.6.3'  #audit tag
            match_output: '2'   #expected value of the checked parameter
      'CentOS-7':
        - 'kernel.randomize_va_space':
            tag: 'CIS-1.6.2'
            match_output: '2'
    description: 'Enable Randomized Virtual Memory Region Placement (Scored)'
    labels:
      - critical
    alert: email
    trigger: state
'''

from __future__ import absolute_import
import logging

import fnmatch
import copy
import salt.utils
import salt.utils.platform

from distutils.version import LooseVersion

log = logging.getLogger(__name__)


def __virtual__():
    if salt.utils.platform.is_windows():
        return False, 'This audit module only runs on linux'
    return True

def apply_labels(__data__, labels):
    '''
    Filters out the tests whose label doesn't match the labels given when running audit and returns a new data structure with only labelled tests.
    '''
    ret={}
    if labels:
        labelled_test_cases=[]
        for test_case in __data__.get('sysctl', []):
            # each test case is a dictionary with just one key-val pair. key=test name, val=test data, description etc
            if isinstance(test_case, dict) and test_case:
                test_case_body = test_case.get(next(iter(test_case)))
                if test_case_body.get('labels') and set(labels).issubset(set(test_case_body.get('labels',[]))):
                    labelled_test_cases.append(test_case)
        ret['sysctl']=labelled_test_cases
    else:
        ret=__data__
    return ret

def audit(data_list, tags, labels, debug=False, **kwargs):
    '''
    Run the sysctl audits contained in the YAML files processed by __virtual__
    '''
    __data__ = {}
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __data__ = apply_labels(__data__, labels)
    __tags__ = _get_tags(__data__)

    if debug:
        log.debug('service audit __data__:')
        log.debug(__data__)
        log.debug('service audit __tags__:')
        log.debug(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}

    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                passed = True
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                name = tag_data['name']
                match_output = tag_data['match_output']

                salt_ret = __salt__['sysctl.get'](name)
                if not salt_ret:
                    passed = False
                    tag_data['failure_reason'] = "Could not find attribute '{0}' in" \
                                                 " the kernel".format(name)
                if str(salt_ret).startswith('error'):
                    passed = False
                    tag_data['failure_reason'] = "An error occured while reading the" \
                                                 " value of kernel attribute '{0}'" \
                                                 .format(name)
                if str(salt_ret) != str(match_output):
                    tag_data['failure_reason'] = "Current value of kernel attribute " \
                                                 "'{0}' is '{1}'. It should be set to '{2}'" \
                                                 .format(name, salt_ret, match_output)
                    passed = False
                if passed:
                    ret['Success'].append(tag_data)
                else:
                    ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    '''
    Merge two yaml dicts together
    '''
    if 'sysctl' not in ret:
        ret['sysctl'] = []
    for key, val in data.get('sysctl', {}).iteritems():
        if profile and isinstance(val, dict):
            val['nova_profile'] = profile
        ret['sysctl'].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for audit_dict in data.get('sysctl', []):
        for audit_id, audit_data in audit_dict.iteritems():
            tags_dict = audit_data.get('data', {})
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
            if isinstance(tags, dict):
                # malformed yaml, convert to list of dicts
                tmp = []
                for name, tag in tags.iteritems():
                    tmp.append({name: tag})
                tags = tmp
            for item in tags:
                for name, tag in item.iteritems():
                    if isinstance(tag, dict):
                        tag_data = copy.deepcopy(tag)
                        tag = tag_data.pop('tag')
                    if tag not in ret:
                        ret[tag] = []
                    formatted_data = {'name': name,
                                      'tag': tag,
                                      'module': 'sysctl'}
                    formatted_data.update(tag_data)
                    formatted_data.update(audit_data)
                    formatted_data.pop('data')
                    ret[tag].append(formatted_data)
    return ret
