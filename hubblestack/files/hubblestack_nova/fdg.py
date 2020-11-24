# -*- encoding: utf-8 -*-
"""
HubbleStack Nova plugin for using fdg to create flexible checks.

This audit module requires yaml data to execute. It will search the local
directory for any .yaml files, and if it finds a top-level 'fdg' key, it will
use that data.

Sample YAML data, with inline comments:


fdg:
  fstab_tmp_partition:  # unique ID
    data:
      CentOS Linux-6:  # osfinger grain
        fdg_file: 'salt://fdg/my_fdg_file.fdg'  # filename for fdg routine
        tag: 'CIS-1.1.1'  # audit tag
        starting_chained: 'value'  # value for fdg `starting_chained` (optional)
        true_for_success: True  # Whether a "truthy" value constitues success
        use_status: False  # Use the status result of the fdg run.
      '*':  # wildcard, will be run if no direct osfinger match
        fdg_file: 'salt://fdg/my_fdg_file.fdg'  # filename for fdg routine
        tag: 'CIS-1.1.1'  # audit tag
    # The rest of these attributes are optional
    description: |
      This is a multi-line description of the fdg routine or reason for this
      check
    labels:
      - critical
      - raiseticket

The ``true_for_success`` argument decides how success/failure are decided
based on the fdg return. By default, any "truthy" value in the ``results`` piece
of the FDG return will constitute success. Set this option to False to treat
"falsey" values as success.

The ``use_status`` argument determines whether the status result or the actual
result returned from fdg will be used. If this is True, only the status result of
the fdg run will be considered. If it is False, only the actual result of the
fdg run will be considered. Regardless, the ``true_for_success`` argument
will be respected.
"""

import logging

import fnmatch
import copy

from salt.exceptions import CommandExecutionError

log = logging.getLogger(__name__)


def audit(data_list, tags, labels, debug=False, **kwargs):
    """
    Run the fdg audits contained in the YAML files in data_list
    """
    __data__ = {}
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __data__ = _apply_labels(__data__, labels)
    __tags__ = _get_tags(__data__)

    if debug:
        log.debug('fdg audit __data__:')
        log.debug(__data__)
        log.debug('fdg audit __tags__:')
        log.debug(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}
    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                name = tag_data['name']

                if 'fdg_file' not in tag_data:
                    log.error('No `fdg_file` argument found for fdg audit {0}, file {1}'
                              .format(tag, name))
                    tag_data = copy.deepcopy(tag_data)
                    tag_data['error'] = 'No fdg_file found'.format(mod)
                    tag_data['failure_reason'] = 'No fdg_file found for the test case.' \
                                                 ' Seems like a bug in hubble profile.'
                    ret['Failure'].append(tag_data)
                    continue

                fdg_file = tag_data['fdg_file']
                starting_chained = tag_data.get('starting_chained')
                true_for_success = tag_data.get('true_for_success', True)
                use_status = tag_data.get('use_status', False)

                _, fdg_run = __salt__['fdg.fdg'](fdg_file, starting_chained=starting_chained)
                fdg_result, fdg_status = fdg_run

                tag_data['fdg_result'] = fdg_result
                tag_data['fdg_status'] = fdg_status

                if use_status:
                    check_value = fdg_status
                else:
                    check_value = fdg_result

                if true_for_success:
                    if check_value:
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)
                else:
                    if check_value:
                        ret['Failure'].append(tag_data)
                    else:
                        ret['Success'].append(tag_data)
    return ret


def _merge_yaml(ret, data, profile=None):
    """
    Merge two yaml dicts together at the fdg level
    """
    if 'fdg' not in ret:
        ret['fdg'] = []
    for key, val in data.get('fdg', {}).items():
        if profile and isinstance(val, dict):
            val['nova_profile'] = profile
        ret['fdg'].append({key: val})
    return ret


def _get_tags(data):
    """
    Retrieve all the tags for this distro from the yaml
    """
    ret = {}
    distro = __grains__.get('osfinger')
    for audit_dict in data.get('fdg', {}):
        # fdg:0
        for audit_id, audit_data in audit_dict.items():
            # fdg:0:id
            tags_dict = audit_data.get('data', {})
            # fdg:0:id:data
            tagged = None
            for osfinger in tags_dict:
                if osfinger == '*':
                    continue
                osfinger_list = [finger.strip() for finger in osfinger.split(',')]
                for osfinger_glob in osfinger_list:
                    if fnmatch.fnmatch(distro, osfinger_glob):
                        tagged = tags_dict.get(osfinger)
                        break
                if tagged is not None:
                    break
            # If we didn't find a match, check for a '*'
            if tagged is None:
                tagged = tags_dict.get('*', None)
            if tagged is None or not isinstance(tagged, dict):
                continue
            # fdg:0:id:data:Debian-8
            formatted_data = {'name': audit_id,
                              'module': 'fdg'}
            formatted_data.update(tagged)
            formatted_data.update(audit_data)
            formatted_data.pop('data')
            tag = formatted_data.get('tag')
            if not tag:
                continue
            if tag not in ret:
                ret[tag] = []
            ret[tag].append(formatted_data)
    return ret


def _apply_labels(__data__, labels):
    """
    Filters out the tests whose label doesn't match the labels given when
    running audit and returns a new data structure with only labelled tests.
    """
    if labels:
        labelled_data = []
        for item in __data__['fdg']:
            if isinstance(item, dict) and item.get('labels'):
                skip = False
                for label in labels:
                    if label not in item['labels']:
                        skip = True
                if skip is False:
                    labelled_data.append(item)
        __data__['fdg'] = labelled_data
    return __data__
