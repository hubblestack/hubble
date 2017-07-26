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


def audit(data_list, tags, debug=False):
    '''
    Run the misc audits contained in the data_list
    '''
    __data__ = {}
    for profile, data in data_list:
        _merge_yaml(__data__, data, profile)
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
                    if 'Errors' not in ret:
                        ret['Errors'] = []
                    ret['Errors'].append({tag: 'No function {0} found'
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

def _execute_shell_command(cmd):
    '''
    This function will execute passed command in /bin/shell
    '''
    return __salt__['cmd.run'](cmd, python_shell=True, shell='/bin/bash')

def check_all_ports_firewall_rules(reason=''):
    '''
    Ensure firewall rule for all open ports
    '''
    end_open_ports = _execute_shell_command('netstat -ln | grep "Active UNIX domain sockets (only servers)" -n  | cut -d ":" -f1')
    start_open_ports = _execute_shell_command('netstat -ln | grep "Active Internet connections (only servers)" -n | cut -d ":" -f1')
    open_ports = _execute_shell_command('netstat -ln | awk \'FNR > ' + start_open_ports + ' && FNR < ' + end_open_ports + ' && $6 == "LISTEN" {print $4}\' | sed -e "s/.*://"')
    firewall_ports = _execute_shell_command('iptables -L INPUT -v -n | awk \'FNR > 2 {print $11}\' | sed -e "s/.*://"')
    if set(open_ports).issubset(set(firewall_ports)):
        return True
    return False

def check_password_fields_not_empty(reason=''):
    '''
    Ensure password fields are not empty
    '''
    result = _execute_shell_command('cat /etc/shadow | awk -F: \'($2 == "" ) { print $1 " does not have a password "}\'')
    if result == '':
      return True
    return result

def ungrouped_files_or_dir(reason=''):
    '''
    Ensure no ungrouped files or directories exist
    '''
    result = _execute_shell_command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nogroup')
    if result == '':
      return True
    return result

def unowned_files_or_dir(reason=''):
    '''
    Ensure no unowned files or directories exist
    '''
    result = _execute_shell_command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -nouser')
    if result == '':
      return True
    return result

def world_writable_file(reason=''):
    '''
    Ensure no world writable files exist
    '''
    result = _execute_shell_command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type f -perm -0002')
    if result == '':
      return True
    return result

def system_account_non_login(reason=''):
    '''
    Ensure system accounts are non-login
    '''
    result = _execute_shell_command('egrep -v "^\+" /etc/passwd | awk -F: \'($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false") {print}\'')
    if result == '':
      return True
    return result

def sticky_bit_on_world_writable_dirs(reason=''):
    '''
    Ensure sticky bit is set on all world-writable directories
    '''
    result = _execute_shell_command('df --local -P | awk {\'if (NR!=1) print $6\'} | xargs -I \'{}\' find \'{}\' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null')
    if result == '':
      return True
    return result

def default_group_for_root(reason=''):
    '''
    Ensure default group for the root account is GID 0
    '''
    result = _execute_shell_command('grep "^root:" /etc/passwd | cut -f4 -d:')
    result = result.strip()
    if result == '0':
      return True
    return False

def root_is_only_uid_0_account(reason=''):
    '''
    Ensure root is the only UID 0 account
    '''
    result = _execute_shell_command('cat /etc/passwd | awk -F: \'($3 == 0) { print $1 }\'')
    if result.strip() == 'root':
      return True
    return result

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
    'check_all_ports_firewall_rules': check_all_ports_firewall_rules,
    'check_password_fields_not_empty': check_password_fields_not_empty,
    'ungrouped_files_or_dir': ungrouped_files_or_dir,
    'unowned_files_or_dir': unowned_files_or_dir,
    'world_writable_file': world_writable_file,
    'system_account_non_login': system_account_non_login,
    'sticky_bit_on_world_writable_dirs': sticky_bit_on_world_writable_dirs,
    'default_group_for_root': default_group_for_root,
    'root_is_only_uid_0_account': root_is_only_uid_0_account,
    'test_success': test_success,
    'test_failure': test_failure,
    'test_failure_reason': test_failure_reason,
}
