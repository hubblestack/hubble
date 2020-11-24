# -*- encoding: utf-8 -*-
"""
Hubble Nova plugin for running arbitrary commands and checking the output of
those commands

This module is deprecated, and must be explicitly enabled in pillar/minion
config via the hubblestack:nova:enable_command_module (should be set to True
to enable this module). This allows nova to run arbitrary commands via yaml
profiles.

Sample YAML data, with inline comments:

# Top level key lets the module know it should look at this data
command:
  # Unique ID for this set of audits
  nodev:
    data:
      # 'osfinger' grain, for multiplatform support
      'Red Hat Enterprise Linux Server-6':
        # tag is required
        tag: CIS-1.1.10
        # `commands` is a list of commands with individual flags
        commands:
          # Command to be run
          - 'grep "[[:space:]]/home[[:space:]]" /etc/fstab':
              # Check the output for this pattern
              # If match_output not provided, any output will be a match
              match_output: nodev
              # Use regex when matching the output (default False)
              match_output_regex: False
              # Invert the success criteria. If True, a match will cause failure (default False)
              fail_if_matched: False
          - 'mount | grep /home':
              match_output: nodev
              match_output_regex: False
              # Match each line of the output against our pattern
              # Any that don't match will make the audit fail (default False)
              match_output_by_line: True
          - ?
              |
                echo 'this is a multi-line'
                echo 'bash script'
                echo 'note the special ? syntax'
            :
              # Shell through which the script will be run, must be abs path
              shell: /bin/bash
              match_output: this
        # Aggregation strategy for multiple commands. Defaults to 'and', other option is 'or'
        aggregation: 'and'
      # Catch-all, if no other osfinger match was found
      '*':
        tag: generic_tag
        commands:
          - 'grep "[[:space:]]/home[[:space:]]" /etc/fstab':
              match_output: nodev
              match_output_regex: False
              fail_if_matched: False
          - 'mount | grep /home':
              match_output: nodev
              match_output_regex: False
              match_output_by_line: True
        aggregation: 'and'
    # Description will be output with the results
    description: '/home should be nodev'
"""

import logging

import fnmatch
import re
import salt.utils

log = logging.getLogger(__name__)


def __virtual__():
    return True


def audit(data_list, tags, labels, **kwargs):
    """
    Run the command audits contained in the data_list
    """
    # Consume any module_params from kwargs (Setting False as a fallback)
    debug = kwargs.get('nova_debug', False)
    cmd_raw = kwargs.get('cmd_raw', False)

    __data__ = {}
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
    __tags__ = _get_tags(__data__)

    if debug:
        log.debug('command audit __data__:')
        log.debug(__data__)
        log.debug('command audit __tags__:')
        log.debug(__tags__)

    ret = {'Success': [], 'Failure': [], 'Controlled': []}

    if __tags__ and not __salt__['config.get']('hubblestack:nova:enable_command_module',
                                               False):
        ret['Errors'] = ['command module has not been explicitly enabled in '
                         'config. Please set hubblestack:nova:enable_command_module '
                         'to True in pillar or minion config to allow this module.']
        return ret

    for tag in __tags__:
        if fnmatch.fnmatch(tag, tags):
            for tag_data in __tags__[tag]:
                if 'control' in tag_data:
                    ret['Controlled'].append(tag_data)
                    continue
                if 'commands' not in tag_data:
                    continue
                command_results = []
                for command_data in tag_data['commands']:
                    for command, command_args in command_data.items():
                        if 'shell' in command_args:
                            cmd_ret = __salt__['cmd.run'](command,
                                                          python_shell=True,
                                                          shell=command_args['shell'])
                        else:
                            cmd_ret = __salt__['cmd.run'](command,
                                                          python_shell=True)

                        found = False
                        if cmd_ret:
                            if cmd_raw:
                                tag_data['raw'] = cmd_ret
                            found = True

                        if 'match_output' in command_args:

                            if command_args.get('match_output_by_line'):
                                cmd_ret_lines = cmd_ret.splitlines()
                            else:
                                cmd_ret_lines = [cmd_ret]

                            for line in cmd_ret_lines:
                                if command_args.get('match_output_regex'):
                                    if not re.match(command_args['match_output'], line):
                                        found = False
                                else:  # match without regex
                                    if command_args['match_output'] not in line:
                                        found = False

                        if command_args.get('fail_if_matched'):
                            found = not found

                        command_results.append(found)

                aggregation = tag_data.get('aggregation', 'and')

                if aggregation.lower() == 'or':
                    if any(command_results):
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)
                else:  # assume 'and' if it's not 'or'
                    if all(command_results):
                        ret['Success'].append(tag_data)
                    else:
                        ret['Failure'].append(tag_data)

    return ret


def _merge_yaml(ret, data, profile=None):
    """
    Merge two yaml dicts together at the command level
    """
    if 'command' not in ret:
        ret['command'] = []
    if 'command' in data:
        for key, val in data['command'].items():
            if profile and isinstance(val, dict):
                val['nova_profile'] = profile
            ret['command'].append({key: val})
    return ret


def _get_tags(data):
    """
    Retrieve all the tags for this distro from the yaml
    """
    ret = {}
    distro = __grains__.get('osfinger')
    for audit_dict in data.get('command', []):
        # command:0
        for audit_id, audit_data in audit_dict.items():
            # command:0:nodev
            tags_dict = audit_data.get('data', {})
            # command:0:nodev:data
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
            # command:0:nodev:data:Debian-8
            if 'tag' not in tags:
                tags['tag'] = ''
            tag = tags['tag']
            if tag not in ret:
                ret[tag] = []
            formatted_data = {'tag': tag,
                              'module': 'command'}
            formatted_data.update(audit_data)
            formatted_data.update(tags)
            formatted_data.pop('data')
            ret[tag].append(formatted_data)
    return ret
