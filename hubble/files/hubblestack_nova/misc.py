# -*- encoding: utf-8 -*-
'''
Hubble Nova plugin for running miscellaneous one-off python functions to
run more complex nova audits without allowing arbitrary command execution
from within the yaml profiles.

:maintainer: HubbleStack / basepi
:maturity: 2016.7.2
:platform: All
:requires: SaltStack

Sample YAML data, with inline comments:

# Top level key lets the module know it should look at this data
misc:
  # Unique ID for this set of audits
  nodev:
    data:
      # 'osfinger' grain, for multiplatform support
      'Red Hat Enterprise Linux Server-6':
        # tag is required
        tag: CIS-1.1.10
        function: misc_function_name
        args: # optional
          - first_arg
          - second_arg
        kwargs: # optional
          first_kwarg: value
          second_kwarg: value

      # Catch-all, if no other osfinger match was found
      '*':
        tag: generic_tag
        function: misc_function_name
        args: # optional
          - first_arg
          - second_arg
        kwargs: # optional
          first_kwarg: value
          second_kwarg: value
    # Description will be output with the results
    description: '/home should be nodev'
'''
from __future__ import absolute_import
import logging

import fnmatch
import yaml
import os
import copy
import re
import salt.utils
from salt.ext import six

log = logging.getLogger(__name__)


def __virtual__():
    return True


def audit(data_list, tags, verbose=False, show_profile=False, debug=False):
    '''
    Run the misc audits contained in the data_list
    '''
    __data__ = {}
    for profile, data in data_list:
        if show_profile:
            _merge_yaml(__data__, data, profile)
        else:
            _merge_yaml(__data__, data)
    __tags__ = _get_tags(__data__)

    if debug:
        log.debug('misc audit __data__:')
        log.debug(__data__)
        log.debug('misc audit __tags__:')
        log.debug(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}

    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                if 'function' not in tag_data:
                    continue

                function = FUNCTION_MAP.get(tag_data['function'])
                if not function:
                    if 'Error' not in ret:
                        ret['Error'] = []
                    ret['Error'].append({tag: 'No function {0} found'
                                              .format(tag_data['function'])})
                args = tag_data.get('args', [])
                kwargs = tag_data.get('kwargs', {})

                # Call the function
                result = function(*args, **kwargs)

                if result is True:
                    ret['Success'].append(tag_data)
                elif isinstance(result, six.string_types):
                    tag_data['failure_reason'] = result
                    ret['Failure'].append(tag_data)
                else:
                    ret['Failure'].append(tag_data)

    failure = []
    success = []
    controlled = []

    if not verbose:
        # Pull out just the tag and description
        tags_descriptions = set()

        for tag_data in ret['Failure']:
            tag = tag_data['tag']
            description = tag_data.get('description')
            if (tag, description) not in tags_descriptions:
                failure.append({tag: description})
                tags_descriptions.add((tag, description))

        tags_descriptions = set()

        for tag_data in ret['Success']:
            tag = tag_data['tag']
            description = tag_data.get('description')
            if (tag, description) not in tags_descriptions:
                success.append({tag: description})
                tags_descriptions.add((tag, description))

        control_reasons = set()

        for tag_data in ret['Controlled']:
            tag = tag_data['tag']
            control_reason = tag_data.get('control', '')
            description = tag_data.get('description')
            if (tag, description, control_reason) not in control_reasons:
                tag_dict = {'description': description,
                        'control': control_reason}
                controlled.append({tag: tag_dict})
                control_reasons.add((tag, description, control_reason))

    else:
        # Format verbose output as single-key dictionaries with tag as key
        for tag_data in ret['Failure']:
            tag = tag_data['tag']
            failure.append({tag: tag_data})

        for tag_data in ret['Success']:
            tag = tag_data['tag']
            success.append({tag: tag_data})

        for tag_data in ret['Controlled']:
            tag = tag_data['tag']
            controlled.append({tag: tag_data})

    ret['Controlled'] = controlled
    ret['Success'] = success
    ret['Failure'] = failure

    if not ret['Controlled']:
        ret.pop('Controlled')

    return ret


def _merge_yaml(ret, data, profile=None):
    '''
    Merge two yaml dicts together at the misc level
    '''
    if 'misc' not in ret:
        ret['misc'] = []
    if 'misc' in data:
        for key, val in data['misc'].iteritems():
            if profile and isinstance(val, dict):
                val['nova_profile'] = profile
            ret['misc'].append({key: val})
    return ret


def _get_tags(data):
    '''
    Retrieve all the tags for this distro from the yaml
    '''
    ret = {}
    distro = __grains__.get('osfinger')
    for audit_dict in data.get('misc', []):
        # misc:0
        for audit_id, audit_data in audit_dict.iteritems():
            # misc:0:nodev
            tags_dict = audit_data.get('data', {})
            # misc:0:nodev:data
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
                tags = tags_dict.get('*', {})
            # misc:0:nodev:data:Debian-8
            if 'tag' not in tags:
                tags['tag'] = ''
            tag = tags['tag']
            if tag not in ret:
                ret[tag] = []
            formatted_data = {'tag': tag,
                              'module': 'misc'}
            formatted_data.update(audit_data)
            formatted_data.update(tags)
            formatted_data.pop('data')
            ret[tag].append(formatted_data)
    return ret


############################
# Begin function definitions
############################


def test_success():
    '''
    Automatically returns success
    '''
    return True


def test_failure():
    '''
    Automatically returns failure, no reason
    '''
    return False


def test_failure_reason(reason):
    '''
    Automatically returns failure, with a reason (first arg)
    '''
    return reason


FUNCTION_MAP = {
    'test_success': test_success,
    'test_failure': test_failure,
    'test_failure_reason': test_failure_reason,
}
