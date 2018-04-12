# -*- encoding: utf-8 -*-
'''
HubbleStack Nova plugin for verifying attributes associated with a mounted partition.

Supports both blacklisting and whitelisting patterns. Blacklisted patterns must
not be found in the specified file. Whitelisted patterns must be found in the
specified file.

:maintainer: HubbleStack / basepi
:maturity: 2017.8.29
:platform: All
:requires: SaltStack

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'mount' key, it will
use that data.

Sample YAML data, with inline comments:


mount:
  whitelist: # or blacklist
    ensure_nodev_option_on_/tmp:  # unique ID
      data:
        CentOS Linux-6:  # osfinger grain
          - '/tmp':  # path of partition
              tag: 'CIS-1.1.1'  # audit tag
              attribute: nodev  # attribute which must exist for the mounted partition
              check_type: soft  # if 'hard', the check fails if the path doesn't exist or
                                # if it is not a mounted partition. If 'soft', the test passes
                                # for such cases  (default: hard)
      labels:
        - critical
'''
from __future__ import absolute_import
import logging

import fnmatch
import os
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
    labelled_data = {}
    if labels:
        labelled_data['mount'] = {}
        for topkey in ('blacklist', 'whitelist'):
            if topkey in __data__.get('mount', {}):
                labelled_test_cases=[]
                for test_case in __data__['mount'].get(topkey, []):
                    # each test case is a dictionary with just one key-val pair. key=test name, val=test data, description etc
                    if isinstance(test_case, dict) and test_case:
                        test_case_body = test_case.get(next(iter(test_case)))
                        if set(labels).issubset(set(test_case_body.get('labels',[]))):
                            labelled_test_cases.append(test_case)
                labelled_data['mount'][topkey]=labelled_test_cases
    else:
        labelled_data = __data__
    return labelled_data

def audit(data_list, tags, labels, debug=False, **kwargs):
    '''
    Run the mount audits contained in the YAML files processed by __virtual__
    '''

    __data__ = {}

    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __data__ = apply_labels(__data__, labels)
    __tags__ = _get_tags(__data__)

    if debug:
        log.debug('mount audit __data__:')
        log.debug(__data__)
        log.debug('mount audit __tags__:')
        log.debug(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue


                name = tag_data.get('name')
                audittype = tag_data.get('type')

                if 'attribute' not in tag_data:
                    log.error('No attribute found for mount audit {0}, file {1}'
                              .format(tag, name))
                    tag_data = copy.deepcopy(tag_data)
                    tag_data['error'] = 'No pattern found'.format(mod)
                    ret['Failure'].append(tag_data)
                    continue

                attribute = tag_data.get('attribute')

                check_type = 'hard'
                if 'check_type' in tag_data:
                    check_type = tag_data.get('check_type')

                if check_type not in ['hard', 'soft']:
                    log.error('Unrecognized option: ' + check_type)
                    tag_data = copy.deepcopy(tag_data)
                    tag_data['error'] = 'check_type can only be hard or soft'
                    ret['Failure'].append(tag_data)
                    continue

                found = _check_mount_attribute(name, attribute, check_type)

                if audittype == 'blacklist':
                    if found:
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)

                elif audittype == 'whitelist':
                    if found:
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    '''
    Merge two yaml dicts together at the mount:blacklist and mount:whitelist level
    '''
    if 'mount' not in ret:
        ret['mount'] = {}
    for topkey in ('blacklist', 'whitelist'):
        if topkey in data.get('mount', {}):
            if topkey not in ret['mount']:
                ret['mount'][topkey] = []
            for key, val in data['mount'][topkey].iteritems():
                if profile and isinstance(val, dict):
                    val['nova_profile'] = profile
                ret['mount'][topkey].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''

    ret = {}
    distro = __grains__.get('osfinger')

    for toplist, toplevel in data.get('mount', {}).iteritems():
        # mount:blacklist
        for audit_dict in toplevel:
            # mount:blacklist:0
            for audit_id, audit_data in audit_dict.iteritems():
                # mount:blacklist:0:telnet
                tags_dict = audit_data.get('data', {})
                # mount:blacklist:0:telnet:data
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
                # mount:blacklist:0:telnet:data:Debian-8
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
                                          'module': 'mount',
                                          'type': toplist}
                        formatted_data.update(tag_data)
                        formatted_data.update(audit_data)
                        formatted_data.pop('data')
                        ret[tag].append(formatted_data)
    return ret


def _check_mount_attribute(path, attribute, check_type):
    '''
    This function checks if the partition at a given path is mounted with a particular attribute or not.
    If 'check_type' is 'hard', the function returns False if he specified path does not exist, or if it
    is not a mounted partition. If 'check_type' is 'soft', the functions returns True in such cases.
    '''

    if not os.path.exists(path):
        if check_type == 'hard':
            return False
        else:
            return True

    mount_object = __salt__['mount.active']()

    if path in mount_object:
        attributes = mount_object.get(path)
        opts = attributes.get('opts')
        if attribute in opts:
            return True
        else:
            return False

    else:
        if check_type == 'hard':
            return False
        else:
            return True
