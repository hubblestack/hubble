# -*- encoding: utf-8 -*-
'''
HubbleStack Nova module for using stat to verify ownership & permissions.

:maintainer: HubbleStack / avb76
:maturity: 2016.7.0
:platform: Linux
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'stat' key, it will
use that data.

Sample YAML data, with inline comments:


stat:
  grub_conf_own:  # unique ID
    data:
      'CentOS-6':  # osfinger grain
        - '/etc/grub.conf':  # filename
            tag: 'CIS-1.5.1'  #audit tag
            user: 'root'  #expected owner
            uid: 0        #expected uid owner
            group: 'root'  #expected group owner
            gid: 0          #expected gid owner
            match_on_file_missing: True  # See (1) below
      'CentOS Linux-7':
        - '/etc/grub2/grub.cfg':
            tag: 'CIS-1.5.1'
            user: 'root'
            mode: 644
            allow_more_strict: True # file permissions can be 644 or more strict [default = False ]
            uid: 0
            group: 'root'
            gid: 0
    # The rest of these attributes are optional, and currently not used
    description: 'Grub must be owned by root'
    labels:
      - critical
    alert: email
    trigger: state

(1) If `match_on_file_missing` is ommitted, success/failure will be determined
entirely based on the grep command and other arguments. If it's set to True and
the file is missing, then it will be considered a match (success).
If it's set to False and the file is missing, then it
will be considered a non-match (failure).
If the file exists, this setting is ignored.
'''

from __future__ import absolute_import
import logging
import os
import fnmatch
import copy
import salt.utils
import salt.utils.platform

from distutils.version import LooseVersion

log = logging.getLogger(__name__)

__virtualname__ = 'stat'


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
        for test_case in __data__.get('stat', []):
            # each test case is a dictionary with just one key-val pair. key=test name, val=test data, description etc
            if isinstance(test_case, dict) and test_case:
                test_case_body = test_case.get(next(iter(test_case)))
                if test_case_body.get('labels') and set(labels).issubset(set(test_case_body.get('labels',[]))):
                    labelled_test_cases.append(test_case)
        ret['stat']=labelled_test_cases
    else:
        ret=__data__
    return ret    

def audit(data_list, tags, labels, debug=False, **kwargs):
    '''
    Run the stat audits contained in the YAML files processed by __virtual__
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
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                name = tag_data['name']
                expected = {}
                for e in ['mode', 'user', 'uid', 'group', 'gid', 'allow_more_strict', 'match_on_file_missing']:
                    if e in tag_data:
                        expected[e] = tag_data[e]

                if 'allow_more_strict' in expected.keys() and 'mode' not in expected.keys():
                    reason_dict = {}
                    reason = "'allow_more_strict' tag can't be specified without 'mode' tag." \
                             " Seems like a bug in hubble profile."
                    reason_dict['allow_more_strict'] = reason
                    tag_data['failure_reason'] = "For file '{0}': {1}".format(name, reason_dict)
                    ret['Failure'].append(tag_data)
                    continue

                # getting the stats using salt
                if os.path.exists(name):
                    salt_ret = __salt__['file.stats'](name)
                else:
                    salt_ret = {}
                if not salt_ret:
                    if not expected:
                        ret['Success'].append(tag_data)
                    elif 'match_on_file_missing' in expected.keys() and expected['match_on_file_missing']:
                        ret['Success'].append(tag_data)
                    else:
                        tag_data['failure_reason'] = "Could not get access any file at '{0}'. " \
                                                     "File might not exist, or hubble might not" \
                                                     " have enough permissions".format(name)
                        ret['Failure'].append(tag_data)
                    continue

                passed = True
                reason_dict = {}
                for e in expected.keys():
                    if e == 'allow_more_strict' or e == 'match_on_file_missing':
                        continue
                    r = salt_ret[e]

                    if e == 'mode':
                        if r != '0':
                            r = r[1:]
                        allow_more_strict = False
                        if 'allow_more_strict' in expected.keys():
                            allow_more_strict = expected['allow_more_strict']
                        if not isinstance(allow_more_strict, bool):
                            passed = False
                            reason = "{0} is not a valid boolean. Seems like a bug in hubble profile." \
                                     .format(allow_more_strict)
                            reason_dict[e] = reason

                        else:
                            subcheck_passed = _check_mode(str(expected[e]), str(r), allow_more_strict)
                            if not subcheck_passed:
                                passed = False
                                reason = {'expected': str(expected[e]),
                                          'allow_more_strict': str(allow_more_strict),
                                          'current': str(r)}
                                reason_dict[e] = reason
                    else:
                        subcheck_passed = (str(expected[e]) == str(r))
                        if not subcheck_passed:
                            passed = False
                            reason = {'expected': str(expected[e]),
                                      'current': str(r)}
                            reason_dict[e] = reason

                if reason_dict:
                    tag_data['failure_reason'] = "For file '{0}': {1}".format(name, reason_dict)

                if passed:
                    ret['Success'].append(tag_data)
                else:
                    ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    '''
    Merge two yaml dicts together
    '''
    if 'stat' not in ret:
        ret['stat'] = []
    for key, val in data.get('stat', {}).iteritems():
        if profile and isinstance(val, dict):
            val['nova_profile'] = profile
        ret['stat'].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for audit_dict in data.get('stat', []):
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
                                      'module': 'stat'}
                    formatted_data.update(tag_data)
                    formatted_data.update(audit_data)
                    formatted_data.pop('data')
                    ret[tag].append(formatted_data)
    return ret


def _check_mode(max_permission, given_permission, allow_more_strict):
    '''
    Checks whether a file's permission are equal to a given permission or more restrictive.
    Permission is a string of 3 digits [0-7]. 'given_permission' is the actual permission on file,
    'max_permission' is the expected permission on this file. Set 'allow_more_strict' to True,
    to allow more restrictive permissions as well. Example:

    _check_mode('644', '644', False)        returns         True
    _check_mode('644', '600', False)        returns         False
    _check_mode('644', '644', True)         returns         True
    _check_mode('644', '600', True)         returns         True
    _check_mode('644', '655', True)        returns         False

    '''

    if given_permission == '0':
        return True

    if ((not allow_more_strict) or (max_permission == 'None')):
        return (max_permission == given_permission)

    if (_is_permission_in_limit(max_permission[0], given_permission[0]) and _is_permission_in_limit(max_permission[1], given_permission[1]) and _is_permission_in_limit(max_permission[2], given_permission[2])):
        return True

    return False


def _is_permission_in_limit(max_permission, given_permission):
    '''
    Return true only if given_permission is not more lenient that max_permission. In other words, if
    r or w or x is present in given_permission but absent in max_permission, it should return False
    Takes input two integer values from 0 to 7.
    '''
    max_permission = int(max_permission)
    given_permission = int(given_permission)
    allowed_r = False
    allowed_w = False
    allowed_x = False
    given_r = False
    given_w = False
    given_x = False

    if max_permission >= 4:
        allowed_r = True
        max_permission = max_permission - 4
    if max_permission >= 2:
        allowed_w = True
        max_permission = max_permission - 2
    if max_permission >= 1:
        allowed_x = True

    if given_permission >= 4:
        given_r = True
        given_permission = given_permission - 4
    if given_permission >= 2:
        given_w = True
        given_permission = given_permission - 2
    if given_permission >= 1:
        given_x = True

    if given_r and (not allowed_r):
        return False
    if given_w and (not allowed_w):
        return False
    if given_x and (not allowed_x):
        return False

    return True
